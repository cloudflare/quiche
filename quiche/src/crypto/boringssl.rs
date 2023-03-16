use super::*;

use std::mem::MaybeUninit;

use libc::c_int;

// NOTE: This structure is copied from <openssl/aead.h> in order to be able to
// statically allocate it. While it is not often modified upstream, it needs to
// be kept in sync.
#[repr(C)]
struct EVP_AEAD_CTX {
    aead: libc::uintptr_t,
    opaque: [u8; 580],
    alignment: u64,
    tag_len: u8,
}

impl Algorithm {
    fn get_evp_aead(self) -> *const EVP_AEAD {
        match self {
            Algorithm::AES128_GCM => unsafe { EVP_aead_aes_128_gcm() },
            Algorithm::AES256_GCM => unsafe { EVP_aead_aes_256_gcm() },
            Algorithm::ChaCha20_Poly1305 => unsafe {
                EVP_aead_chacha20_poly1305()
            },
        }
    }
}

impl Open {
    pub fn open_with_u64_counter(
        &self, counter: u64, ad: &[u8], buf: &mut [u8],
    ) -> Result<usize> {
        if cfg!(feature = "fuzzing") {
            return Ok(buf.len());
        }

        let tag_len = self.alg().tag_len();

        let mut out_len = match buf.len().checked_sub(tag_len) {
            Some(n) => n,
            None => return Err(Error::CryptoFail),
        };

        let max_out_len = out_len;

        let nonce = make_nonce(&self.packet.nonce, counter);

        let rc = unsafe {
            EVP_AEAD_CTX_open(
                &self.packet.ctx,   // ctx
                buf.as_mut_ptr(),   // out
                &mut out_len,       // out_len
                max_out_len,        // max_out_len
                nonce[..].as_ptr(), // nonce
                nonce.len(),        // nonce_len
                buf.as_ptr(),       // inp
                buf.len(),          // in_len
                ad.as_ptr(),        // ad
                ad.len(),           // ad_len
            )
        };

        if rc != 1 {
            return Err(Error::CryptoFail);
        }
        Ok(out_len)
    }
}

impl Seal {
    pub fn seal_with_u64_counter(
        &self, counter: u64, ad: &[u8], buf: &mut [u8], in_len: usize,
        extra_in: Option<&[u8]>,
    ) -> Result<usize> {
        if cfg!(feature = "fuzzing") {
            if let Some(extra) = extra_in {
                buf[in_len..in_len + extra.len()].copy_from_slice(extra);
                return Ok(in_len + extra.len());
            }

            return Ok(in_len);
        }

        let tag_len = self.alg().tag_len();

        let mut out_tag_len = tag_len;

        let (extra_in_ptr, extra_in_len) = match extra_in {
            Some(v) => (v.as_ptr(), v.len()),

            None => (std::ptr::null(), 0),
        };

        // Make sure all the outputs combined fit in the buffer.
        if in_len + tag_len + extra_in_len > buf.len() {
            return Err(Error::CryptoFail);
        }

        let nonce = make_nonce(&self.packet.nonce, counter);

        let rc = unsafe {
            EVP_AEAD_CTX_seal_scatter(
                &self.packet.ctx,           // ctx
                buf.as_mut_ptr(),           // out
                buf[in_len..].as_mut_ptr(), // out_tag
                &mut out_tag_len,           // out_tag_len
                tag_len + extra_in_len,     // max_out_tag_len
                nonce[..].as_ptr(),         // nonce
                nonce.len(),                // nonce_len
                buf.as_ptr(),               // inp
                in_len,                     // in_len
                extra_in_ptr,               // extra_in
                extra_in_len,               // extra_in_len
                ad.as_ptr(),                // ad
                ad.len(),                   // ad_len
            )
        };
        if rc != 1 {
            return Err(Error::CryptoFail);
        }

        Ok(in_len + out_tag_len)
    }
}

fn make_aead_ctx(alg: Algorithm, key: &[u8]) -> Result<EVP_AEAD_CTX> {
    let mut ctx = MaybeUninit::uninit();

    let ctx = unsafe {
        let aead = alg.get_evp_aead();

        let rc = EVP_AEAD_CTX_init(
            ctx.as_mut_ptr(),
            aead,
            key.as_ptr(),
            alg.key_len(),
            alg.tag_len(),
            std::ptr::null_mut(),
        );

        if rc != 1 {
            return Err(Error::CryptoFail);
        }

        ctx.assume_init()
    };

    Ok(ctx)
}

pub(crate) struct PacketKey {
    ctx: EVP_AEAD_CTX,
    nonce: Vec<u8>,
}

impl PacketKey {
    pub fn new(
        alg: Algorithm, key: Vec<u8>, iv: Vec<u8>, _enc: u32,
    ) -> Result<Self> {
        Ok(Self {
            ctx: make_aead_ctx(alg, &key)?,
            nonce: iv,
        })
    }

    pub fn from_secret(aead: Algorithm, secret: &[u8], enc: u32) -> Result<Self> {
        let key_len = aead.key_len();
        let nonce_len = aead.nonce_len();

        let mut key = vec![0; key_len];
        let mut iv = vec![0; nonce_len];

        derive_pkt_key(aead, secret, &mut key)?;
        derive_pkt_iv(aead, secret, &mut iv)?;

        Self::new(aead, key, iv, enc)
    }
}

extern {
    fn EVP_aead_aes_128_gcm() -> *const EVP_AEAD;

    fn EVP_aead_aes_256_gcm() -> *const EVP_AEAD;

    fn EVP_aead_chacha20_poly1305() -> *const EVP_AEAD;

    // EVP_AEAD_CTX
    fn EVP_AEAD_CTX_init(
        ctx: *mut EVP_AEAD_CTX, aead: *const EVP_AEAD, key: *const u8,
        key_len: usize, tag_len: usize, engine: *mut c_void,
    ) -> c_int;

    fn EVP_AEAD_CTX_open(
        ctx: *const EVP_AEAD_CTX, out: *mut u8, out_len: *mut usize,
        max_out_len: usize, nonce: *const u8, nonce_len: usize, inp: *const u8,
        in_len: usize, ad: *const u8, ad_len: usize,
    ) -> c_int;

    fn EVP_AEAD_CTX_seal_scatter(
        ctx: *const EVP_AEAD_CTX, out: *mut u8, out_tag: *mut u8,
        out_tag_len: *mut usize, max_out_tag_len: usize, nonce: *const u8,
        nonce_len: usize, inp: *const u8, in_len: usize, extra_in: *const u8,
        extra_in_len: usize, ad: *const u8, ad_len: usize,
    ) -> c_int;
}
