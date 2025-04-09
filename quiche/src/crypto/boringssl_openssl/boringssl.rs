use super::*;

use std::convert::TryFrom;

use std::mem::MaybeUninit;

use libc::c_int;
use libc::c_uint;
use libc::c_void;

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

#[derive(Clone)]
#[repr(C)]
pub(crate) struct AES_KEY {
    rd_key: [u32; 4 * (14 + 1)],
    rounds: c_int,
}

impl Algorithm {
    fn get_evp_aead(self) -> *const EVP_AEAD {
        match self {
            Algorithm::AES128_GCM => unsafe { EVP_aead_aes_128_gcm_tls13() },
            Algorithm::AES256_GCM => unsafe { EVP_aead_aes_256_gcm_tls13() },
            Algorithm::ChaCha20_Poly1305 => unsafe {
                EVP_aead_chacha20_poly1305()
            },
        }
    }
}

pub(crate) struct PacketKey {
    alg: Algorithm,

    ctx: EVP_AEAD_CTX,

    nonce: Vec<u8>,
}

impl PacketKey {
    pub fn new(
        alg: Algorithm, key: Vec<u8>, iv: Vec<u8>, _enc: u32,
    ) -> Result<Self> {
        Ok(Self {
            alg,
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

        let pkt_key = Self::new(aead, key, iv, enc)?;

        // Dummy seal operation to prime the AEAD context with the nonce mask.
        //
        // This is needed because BoringCrypto requires the first counter (i.e.
        // packet number) to be zero, which would not be the case for packet
        // number spaces after Initial as the same packet number sequence is
        // shared.
        let _ = pkt_key.seal_with_u64_counter(0, b"", &mut [0_u8; 16], 0, None);

        Ok(pkt_key)
    }

    pub fn open_with_u64_counter(
        &self, counter: u64, ad: &[u8], buf: &mut [u8],
    ) -> Result<usize> {
        let tag_len = self.alg.tag_len();

        let mut out_len = match buf.len().checked_sub(tag_len) {
            Some(n) => n,
            None => return Err(Error::CryptoFail),
        };

        let max_out_len = out_len;

        let nonce = make_nonce(&self.nonce, counter);

        let rc = unsafe {
            EVP_AEAD_CTX_open(
                &self.ctx,          // ctx
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

    pub fn seal_with_u64_counter(
        &self, counter: u64, ad: &[u8], buf: &mut [u8], in_len: usize,
        extra_in: Option<&[u8]>,
    ) -> Result<usize> {
        let tag_len = self.alg.tag_len();

        let mut out_tag_len = tag_len;

        let (extra_in_ptr, extra_in_len) = match extra_in {
            Some(v) => (v.as_ptr(), v.len()),

            None => (std::ptr::null(), 0),
        };

        // Make sure all the outputs combined fit in the buffer.
        if in_len + tag_len + extra_in_len > buf.len() {
            return Err(Error::CryptoFail);
        }

        let nonce = make_nonce(&self.nonce, counter);

        let rc = unsafe {
            EVP_AEAD_CTX_seal_scatter(
                &self.ctx,                  // ctx
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

#[derive(Clone)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum HeaderProtectionKey {
    Aes(AES_KEY),

    ChaCha(Vec<u8>),
}

impl HeaderProtectionKey {
    pub fn new(alg: Algorithm, hp_key: Vec<u8>) -> Result<Self> {
        match alg {
            Algorithm::AES128_GCM | Algorithm::AES256_GCM => unsafe {
                let key_len_bits = alg.key_len() as u32 * 8;

                let mut aes_key = MaybeUninit::<AES_KEY>::uninit();

                let rc = AES_set_encrypt_key(
                    hp_key.as_ptr(),
                    key_len_bits,
                    aes_key.as_mut_ptr(),
                );

                if rc != 0 {
                    return Err(Error::CryptoFail);
                }

                let aes_key = aes_key.assume_init();
                Ok(Self::Aes(aes_key))
            },

            Algorithm::ChaCha20_Poly1305 => Ok(Self::ChaCha(hp_key)),
        }
    }

    pub fn new_mask(&self, sample: &[u8]) -> Result<HeaderProtectionMask> {
        match self {
            Self::Aes(aes_key) => {
                let mut block = [0_u8; 16];

                unsafe {
                    AES_ecb_encrypt(
                        sample.as_ptr(),
                        block.as_mut_ptr(),
                        aes_key as _,
                        1,
                    )
                };

                // Downsize the encrypted block to the size of the header
                // protection mask.
                //
                // The length of the slice will always match the size of
                // `HeaderProtectionMask` so the `unwrap()` is safe.
                let new_mask =
                    HeaderProtectionMask::try_from(&block[..HP_MASK_LEN])
                        .unwrap();
                Ok(new_mask)
            },

            Self::ChaCha(key) => {
                const PLAINTEXT: &[u8; HP_MASK_LEN] = &[0_u8; HP_MASK_LEN];

                let mut new_mask = HeaderProtectionMask::default();

                let counter = u32::from_le_bytes([
                    sample[0], sample[1], sample[2], sample[3],
                ]);

                unsafe {
                    CRYPTO_chacha_20(
                        new_mask.as_mut_ptr(),
                        PLAINTEXT.as_ptr(),
                        PLAINTEXT.len(),
                        key.as_ptr(),
                        sample[std::mem::size_of::<u32>()..].as_ptr(),
                        counter,
                    );
                };

                Ok(new_mask)
            },
        }
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

pub(crate) fn hkdf_extract(
    alg: Algorithm, out: &mut [u8], secret: &[u8], salt: &[u8],
) -> Result<()> {
    let mut out_len = out.len();

    let rc = unsafe {
        HKDF_extract(
            out.as_mut_ptr(),
            &mut out_len,
            alg.get_evp_digest(),
            secret.as_ptr(),
            secret.len(),
            salt.as_ptr(),
            salt.len(),
        )
    };

    if rc != 1 {
        return Err(Error::CryptoFail);
    }

    Ok(())
}

pub(crate) fn hkdf_expand(
    alg: Algorithm, out: &mut [u8], secret: &[u8], info: &[u8],
) -> Result<()> {
    let rc = unsafe {
        HKDF_expand(
            out.as_mut_ptr(),
            out.len(),
            alg.get_evp_digest(),
            secret.as_ptr(),
            secret.len(),
            info.as_ptr(),
            info.len(),
        )
    };

    if rc != 1 {
        return Err(Error::CryptoFail);
    }

    Ok(())
}

extern "C" {
    fn EVP_aead_aes_128_gcm_tls13() -> *const EVP_AEAD;

    fn EVP_aead_aes_256_gcm_tls13() -> *const EVP_AEAD;

    fn EVP_aead_chacha20_poly1305() -> *const EVP_AEAD;

    // HKDF
    fn HKDF_extract(
        out_key: *mut u8, out_len: *mut usize, digest: *const EVP_MD,
        secret: *const u8, secret_len: usize, salt: *const u8, salt_len: usize,
    ) -> c_int;

    fn HKDF_expand(
        out_key: *mut u8, out_len: usize, digest: *const EVP_MD, prk: *const u8,
        prk_len: usize, info: *const u8, info_len: usize,
    ) -> c_int;

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

    // AES
    fn AES_set_encrypt_key(
        key: *const u8, bits: c_uint, aeskey: *mut AES_KEY,
    ) -> c_int;

    fn AES_ecb_encrypt(
        inp: *const u8, out: *mut u8, key: *const AES_KEY, enc: c_int,
    ) -> c_void;

    // ChaCha20
    fn CRYPTO_chacha_20(
        out: *mut u8, inp: *const u8, in_len: usize, key: *const u8,
        nonce: *const u8, counter: u32,
    ) -> c_void;
}
