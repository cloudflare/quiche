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
struct EVP_PKEY_CTX {
    _unused: c_void,
}

#[allow(non_camel_case_types)]
#[repr(transparent)]
struct OSSL_PARAM {
    _unused: c_void,
}

impl Algorithm {
    pub fn get_evp(self) -> *const EVP_AEAD {
        match self {
            Algorithm::AES128_GCM => unsafe { EVP_aes_128_ctr() },
            Algorithm::AES256_GCM => unsafe { EVP_aes_256_ctr() },
            Algorithm::ChaCha20_Poly1305 => unsafe { EVP_chacha20() },
        }
    }

    pub fn get_evp_aead(self) -> *const EVP_AEAD {
        match self {
            Algorithm::AES128_GCM => unsafe { EVP_aes_128_gcm() },
            Algorithm::AES256_GCM => unsafe { EVP_aes_256_gcm() },
            Algorithm::ChaCha20_Poly1305 => unsafe { EVP_chacha20_poly1305() },
        }
    }
}

pub(crate) struct PacketKey {
    alg: Algorithm,

    ctx: *mut EVP_CIPHER_CTX,

    nonce: Vec<u8>,

    // Note: We'd need the key for later use as it is needed by the openssl API.
    // TODO: check if we can avoid this and get the key when needed and not
    // have it stored here.
    key: Vec<u8>,
}

impl PacketKey {
    pub fn new(
        alg: Algorithm, key: Vec<u8>, iv: Vec<u8>, enc: u32,
    ) -> Result<Self> {
        Ok(Self {
            alg,
            ctx: make_evp_cipher_ctx_basic(alg, true, enc)?,
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

    pub fn open_with_u64_counter(
        &self, counter: u64, ad: &[u8], buf: &mut [u8],
    ) -> Result<usize> {
        let tag_len = self.alg.tag_len();

        let in_buf = buf.to_owned(); // very inefficient

        let mut cipher_len = buf.len();

        let nonce = make_nonce(&self.nonce, counter);

        // Set the IV len.
        const EVP_CTRL_AEAD_SET_IVLEN: i32 = 0x9;
        let mut rc = unsafe {
            EVP_CIPHER_CTX_ctrl(
                self.ctx,
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
                self.ctx,
                std::ptr::null_mut(), // already set
                self.key.as_ptr(),
                nonce[..].as_ptr(),
                Open::DECRYPT as i32,
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
                    self.ctx,
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
                self.ctx,
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
                self.ctx,
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
                self.ctx,
                buf[plaintext_len..].as_mut_ptr(),
                &mut olen,
            )
        };

        if rc != 1 {
            return Err(Error::CryptoFail);
        }

        Ok(plaintext_len + olen as usize)
    }

    pub fn seal_with_u64_counter(
        &self, counter: u64, ad: &[u8], buf: &mut [u8], in_len: usize,
        _extra_in: Option<&[u8]>,
    ) -> Result<usize> {
        let tag_len = self.alg.tag_len();

        // TODO: replace this with something more efficient.
        let in_buf = buf.to_owned();

        let nonce = make_nonce(&self.nonce, counter);

        // Set the IV len.
        const EVP_CTRL_AEAD_SET_IVLEN: i32 = 0x9;
        let mut rc = unsafe {
            EVP_CIPHER_CTX_ctrl(
                self.ctx,
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
                self.ctx,
                std::ptr::null_mut(), // already set
                self.key.as_ptr(),
                nonce[..].as_ptr(),
                Seal::ENCRYPT as i32,
                std::ptr::null(),
            )
        };
        if rc != 1 {
            return Err(Error::CryptoFail);
        }

        let mut olen: i32 = 0;
        let mut rc;

        if !ad.is_empty() {
            rc = unsafe {
                EVP_CipherUpdate(
                    self.ctx,
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
                self.ctx,
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
            EVP_CipherFinal_ex(self.ctx, buf[len..].as_mut_ptr(), &mut olen)
        };

        if rc != 1 {
            return Err(Error::CryptoFail);
        }

        ciphertext_len += olen as usize;

        const EVP_CTRL_AEAD_GET_TAG: i32 = 0x10;
        rc = unsafe {
            EVP_CIPHER_CTX_ctrl(
                self.ctx,
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

impl Drop for PacketKey {
    fn drop(&mut self) {
        unsafe { EVP_CIPHER_CTX_free(self.ctx) }
    }
}

unsafe impl std::marker::Send for PacketKey {}
unsafe impl std::marker::Sync for PacketKey {}

pub(crate) struct HeaderProtectionKey {
    ctx: *mut EVP_CIPHER_CTX,

    key: Vec<u8>,
}

impl HeaderProtectionKey {
    pub fn new(alg: Algorithm, hp_key: Vec<u8>) -> Result<Self> {
        Ok(Self {
            ctx: make_evp_cipher_ctx_basic(alg, false, 1)?,
            key: hp_key,
        })
    }

    pub fn new_mask(&self, sample: &[u8]) -> Result<HeaderProtectionMask> {
        const PLAINTEXT: &[u8; 5] = &[0_u8; 5];

        let mut new_mask = HeaderProtectionMask::default();

        // Set IV (i.e. the sample).
        let rc = unsafe {
            EVP_CipherInit_ex2(
                self.ctx,
                std::ptr::null_mut(), // already set
                self.key.as_ptr(),
                sample.as_ptr(),
                -1,
                std::ptr::null(),
            )
        };

        if rc != 1 {
            return Err(Error::CryptoFail);
        }

        let mut out_len: i32 = 0;

        let rc = unsafe {
            EVP_CipherUpdate(
                self.ctx,
                new_mask.as_mut_ptr(),
                &mut out_len,
                PLAINTEXT.as_ptr(),
                PLAINTEXT.len() as i32,
            )
        };

        if rc != 1 {
            return Err(Error::CryptoFail);
        };

        let rc = unsafe {
            EVP_CipherFinal_ex(
                self.ctx,
                new_mask[out_len as usize..].as_mut_ptr(),
                &mut out_len,
            )
        };

        if rc != 1 {
            return Err(Error::CryptoFail);
        }

        Ok(new_mask)
    }
}

impl Clone for HeaderProtectionKey {
    fn clone(&self) -> Self {
        let ctx = unsafe { EVP_CIPHER_CTX_dup(self.ctx) };

        Self {
            ctx,
            key: self.key.clone(),
        }
    }
}

impl Drop for HeaderProtectionKey {
    fn drop(&mut self) {
        unsafe { EVP_CIPHER_CTX_free(self.ctx) }
    }
}

unsafe impl std::marker::Send for HeaderProtectionKey {}
unsafe impl std::marker::Sync for HeaderProtectionKey {}

fn make_evp_cipher_ctx_basic(
    alg: Algorithm, aead: bool, enc: u32,
) -> Result<*mut EVP_CIPHER_CTX> {
    let ctx: *mut EVP_CIPHER_CTX = unsafe {
        let cipher: *const EVP_AEAD = if aead {
            alg.get_evp_aead()
        } else {
            alg.get_evp()
        };

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

pub(crate) fn hkdf_extract(
    alg: Algorithm, out: &mut [u8], secret: &[u8], salt: &[u8],
) -> Result<()> {
    let mut out_len = out.len();

    unsafe {
        let prf = alg.get_evp_digest();

        let ctx = EVP_PKEY_CTX_new_id(
            1036, // EVP_PKEY_HKDF
            std::ptr::null_mut(),
        );

        if EVP_PKEY_derive_init(ctx) != 1 ||
            EVP_PKEY_CTX_set_hkdf_mode(
                ctx, 1, // EVP_PKEY_HKDF_MODE_EXTRACT_ONLY
            ) != 1 ||
            EVP_PKEY_CTX_set_hkdf_md(ctx, prf) != 1 ||
            EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt.as_ptr(), salt.len()) != 1 ||
            EVP_PKEY_CTX_set1_hkdf_key(ctx, secret.as_ptr(), secret.len()) != 1 ||
            EVP_PKEY_derive(ctx, out.as_mut_ptr(), &mut out_len) != 1
        {
            EVP_PKEY_CTX_free(ctx);
            return Err(Error::CryptoFail);
        }

        EVP_PKEY_CTX_free(ctx);
    }

    Ok(())
}

pub(crate) fn hkdf_expand(
    alg: Algorithm, out: &mut [u8], secret: &[u8], info: &[u8],
) -> Result<()> {
    let mut out_len = out.len();

    unsafe {
        let prf = alg.get_evp_digest();

        let ctx = EVP_PKEY_CTX_new_id(
            1036, // EVP_PKEY_HKDF
            std::ptr::null_mut(),
        );

        if EVP_PKEY_derive_init(ctx) != 1 ||
            EVP_PKEY_CTX_set_hkdf_mode(
                ctx, 2, // EVP_PKEY_HKDF_MODE_EXPAND_ONLY
            ) != 1 ||
            EVP_PKEY_CTX_set_hkdf_md(ctx, prf) != 1 ||
            EVP_PKEY_CTX_set1_hkdf_key(ctx, secret.as_ptr(), secret.len()) != 1 ||
            EVP_PKEY_CTX_add1_hkdf_info(ctx, info.as_ptr(), info.len()) != 1 ||
            EVP_PKEY_derive(ctx, out.as_mut_ptr(), &mut out_len) != 1
        {
            EVP_PKEY_CTX_free(ctx);
            return Err(Error::CryptoFail);
        }

        EVP_PKEY_CTX_free(ctx);
    }

    Ok(())
}

extern "C" {
    // EVP
    fn EVP_aes_128_ctr() -> *const EVP_AEAD;
    fn EVP_aes_128_gcm() -> *const EVP_AEAD;

    fn EVP_aes_256_ctr() -> *const EVP_AEAD;
    fn EVP_aes_256_gcm() -> *const EVP_AEAD;

    fn EVP_chacha20() -> *const EVP_AEAD;
    fn EVP_chacha20_poly1305() -> *const EVP_AEAD;

    // EVP_CIPHER_CTX
    fn EVP_CIPHER_CTX_new() -> *mut EVP_CIPHER_CTX;

    fn EVP_CIPHER_CTX_dup(ctx: *const EVP_CIPHER_CTX) -> *mut EVP_CIPHER_CTX;

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

    // EVP_PKEY
    fn EVP_PKEY_CTX_new_id(id: c_int, e: *mut c_void) -> *mut EVP_PKEY_CTX;

    fn EVP_PKEY_CTX_set_hkdf_mode(ctx: *mut EVP_PKEY_CTX, mode: c_int) -> c_int;
    fn EVP_PKEY_CTX_set_hkdf_md(
        ctx: *mut EVP_PKEY_CTX, md: *const EVP_MD,
    ) -> c_int;
    fn EVP_PKEY_CTX_set1_hkdf_salt(
        ctx: *mut EVP_PKEY_CTX, salt: *const u8, salt_len: usize,
    ) -> c_int;
    fn EVP_PKEY_CTX_set1_hkdf_key(
        ctx: *mut EVP_PKEY_CTX, key: *const u8, key_len: usize,
    ) -> c_int;
    fn EVP_PKEY_CTX_add1_hkdf_info(
        ctx: *mut EVP_PKEY_CTX, info: *const u8, info_len: usize,
    ) -> c_int;

    fn EVP_PKEY_derive_init(ctx: *mut EVP_PKEY_CTX) -> c_int;

    fn EVP_PKEY_derive(
        ctx: *mut EVP_PKEY_CTX, key: *mut u8, key_len: *mut usize,
    ) -> c_int;

    fn EVP_PKEY_CTX_free(ctx: *mut EVP_PKEY_CTX);
}
