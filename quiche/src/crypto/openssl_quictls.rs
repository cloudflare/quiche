use super::*;

use libc::c_int;
use libc::c_uchar;

#[allow(non_camel_case_types)]
#[repr(transparent)]
struct EVP_CIPHER_CTX {
    _unused: *mut EVP_CIPHER_CTX,
}
#[allow(non_camel_case_types)]
#[repr(transparent)]
struct OSSL_PARAM {
    _unused: c_void,
}

impl Drop for EVP_CIPHER_CTX {
    fn drop(&mut self) {
        unsafe { EVP_CIPHER_CTX_free(self) }
    }
}

impl Algorithm {
    pub fn get_evp_aead(self) -> *const EVP_AEAD {
        match self {
            Algorithm::AES128_GCM => unsafe { EVP_aes_128_gcm() },
            Algorithm::AES256_GCM => unsafe { EVP_aes_256_gcm() },
            Algorithm::ChaCha20_Poly1305 => unsafe { EVP_chacha20_poly1305() },
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

        let in_buf = buf.to_owned(); // very inefficient
        let tag_len = self.alg().tag_len();

        let mut cipher_len = buf.len();

        let nonce = make_nonce(&self.packet.nonce, counter);

        // Set the IV len.
        const EVP_CTRL_AEAD_SET_IVLEN: i32 = 0x9;
        let mut rc = unsafe {
            EVP_CIPHER_CTX_ctrl(
                self.packet.ctx,
                EVP_CTRL_AEAD_SET_IVLEN,
                nonce.len() as i32,
                std::ptr::null_mut(),
            )
        };
        if rc != 1 {
            return Err(Error::CryptoFail);
        }

        rc = unsafe {
            EVP_CipherInit_ex2(
                self.packet.ctx,
                std::ptr::null_mut(), // already set
                self.packet.key.as_ptr(),
                nonce[..].as_ptr(),
                Self::DECRYPT as i32,
                std::ptr::null(),
            )
        };

        if rc != 1 {
            return Err(Error::CryptoFail);
        }

        let mut olen: i32 = 0;

        if !ad.is_empty() {
            rc = unsafe {
                EVP_CipherUpdate(
                    self.packet.ctx,
                    std::ptr::null_mut(),
                    &mut olen,
                    ad.as_ptr(),
                    ad.len() as i32,
                )
            };

            if rc != 1 {
                return Err(Error::CryptoFail);
            }
        }

        if cipher_len < tag_len {
            return Err(Error::CryptoFail);
        }

        cipher_len -= tag_len;

        rc = unsafe {
            EVP_CipherUpdate(
                self.packet.ctx,
                buf.as_mut_ptr(),
                &mut olen,
                in_buf.as_ptr(),
                cipher_len as i32,
            )
        };

        if rc != 1 {
            return Err(Error::CryptoFail);
        }

        let plaintext_len = olen as usize;

        const EVP_CTRL_AEAD_SET_TAG: i32 = 0x11;
        rc = unsafe {
            EVP_CIPHER_CTX_ctrl(
                self.packet.ctx,
                EVP_CTRL_AEAD_SET_TAG,
                tag_len as i32,
                buf[cipher_len..].as_mut_ptr() as *mut c_void,
            )
        };

        if rc != 1 {
            return Err(Error::CryptoFail);
        }

        rc = unsafe {
            EVP_CipherFinal_ex(
                self.packet.ctx,
                buf[plaintext_len..].as_mut_ptr(),
                &mut olen,
            )
        };

        if rc != 1 {
            return Err(Error::CryptoFail);
        }

        Ok(plaintext_len + olen as usize)
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
        // very inefficient
        let in_buf = buf.to_owned();

        let nonce = make_nonce(&self.packet.nonce, counter);

        // Set the IV len.
        const EVP_CTRL_AEAD_SET_IVLEN: i32 = 0x9;
        let mut rc = unsafe {
            EVP_CIPHER_CTX_ctrl(
                self.packet.ctx,
                EVP_CTRL_AEAD_SET_IVLEN,
                nonce.len() as i32,
                std::ptr::null_mut(),
            )
        };

        if rc != 1 {
            return Err(Error::CryptoFail);
        }

        rc = unsafe {
            EVP_CipherInit_ex2(
                self.packet.ctx,
                std::ptr::null_mut(), // already set
                self.packet.key.as_ptr(),
                nonce[..].as_ptr(),
                Self::ENCRYPT as i32,
                std::ptr::null(),
            )
        };
        if rc != 1 {
            return Err(Error::CryptoFail);
        }

        let tag_len = self.alg().tag_len();

        let mut olen: i32 = 0;
        let mut rc;

        if !ad.is_empty() {
            rc = unsafe {
                EVP_CipherUpdate(
                    self.packet.ctx,
                    std::ptr::null_mut(),
                    &mut olen,
                    ad.as_ptr(),
                    ad.len() as i32,
                )
            };

            if rc != 1 {
                // We had AD but we couldn't set it.
                return Err(Error::CryptoFail);
            }
        }

        let mut ciphertext_len: usize = 0;

        rc = unsafe {
            EVP_CipherUpdate(
                self.packet.ctx,
                buf.as_mut_ptr(),
                &mut olen,
                in_buf.as_ptr(),
                in_len as i32,
            )
        };

        if rc != 1 {
            return Err(Error::CryptoFail);
        };

        ciphertext_len += olen as usize;

        let len = olen as usize;
        rc = unsafe {
            EVP_CipherFinal_ex(
                self.packet.ctx,
                buf[len..].as_mut_ptr(),
                &mut olen,
            )
        };

        if rc != 1 {
            return Err(Error::CryptoFail);
        }

        ciphertext_len += olen as usize;

        const EVP_CTRL_AEAD_GET_TAG: i32 = 0x10;
        rc = unsafe {
            EVP_CIPHER_CTX_ctrl(
                self.packet.ctx,
                EVP_CTRL_AEAD_GET_TAG,
                tag_len as i32,
                buf[ciphertext_len..].as_mut_ptr() as *mut c_void,
            )
        };

        if rc != 1 {
            return Err(Error::CryptoFail);
        }

        Ok(in_len + tag_len)
    }
}

fn make_evp_cipher_ctx_basic(
    alg: Algorithm, enc: u32,
) -> Result<*mut EVP_CIPHER_CTX> {
    let ctx: *mut EVP_CIPHER_CTX = unsafe {
        let cipher: *const EVP_AEAD = alg.get_evp_aead();

        let ctx = EVP_CIPHER_CTX_new();
        if ctx.is_null() {
            return Err(Error::CryptoFail);
        }

        let rc = EVP_CipherInit_ex2(
            ctx,
            cipher,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            enc as c_int, // Following calls can use -1 once this is set.
            std::ptr::null(),
        );

        if rc != 1 {
            return Err(Error::CryptoFail);
        }
        ctx
    };
    Ok(ctx)
}

pub(crate) struct PacketKey {
    ctx: *mut EVP_CIPHER_CTX,
    nonce: Vec<u8>,
    // Note: We'd need the key for later use as it is needed by the openssl API.
    // TODO: check if we can avoid this and get the key when needed and not
    // have it stored here.
    key: Vec<u8>,
}

impl PacketKey {
    pub fn new(
        algo: Algorithm, key: Vec<u8>, iv: Vec<u8>, enc: u32,
    ) -> Result<Self> {
        Ok(Self {
            ctx: make_evp_cipher_ctx_basic(algo, enc)?,
            nonce: iv,
            key,
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

unsafe impl std::marker::Send for PacketKey {}
unsafe impl std::marker::Sync for PacketKey {}

extern {
    // EVP
    fn EVP_aes_128_gcm() -> *const EVP_AEAD;

    fn EVP_aes_256_gcm() -> *const EVP_AEAD;

    fn EVP_chacha20_poly1305() -> *const EVP_AEAD;

    // EVP_CIPHER_CTX
    fn EVP_CIPHER_CTX_new() -> *mut EVP_CIPHER_CTX;

    fn EVP_CIPHER_CTX_free(ctx: *mut EVP_CIPHER_CTX);

    fn EVP_CipherInit_ex2(
        ctx: *mut EVP_CIPHER_CTX, cipher: *const EVP_AEAD, key: *const c_uchar,
        iv: *const c_uchar, enc: c_int, params: *const OSSL_PARAM,
    ) -> c_int;

    fn EVP_CIPHER_CTX_ctrl(
        ctx: *mut EVP_CIPHER_CTX, type_: i32, arg: i32, ptr: *mut c_void,
    ) -> c_int;

    fn EVP_CipherUpdate(
        ctx: *mut EVP_CIPHER_CTX, out: *mut c_uchar, outl: *mut c_int,
        in_: *const c_uchar, inl: i32,
    ) -> c_int;

    fn EVP_CipherFinal_ex(
        ctx: *mut EVP_CIPHER_CTX, out: *mut c_uchar, outl: *mut c_int,
    ) -> c_int;
}
