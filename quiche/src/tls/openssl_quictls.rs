use super::*;

use libc::c_long;
use libc::c_uchar;

#[allow(non_camel_case_types)]
#[repr(transparent)]
struct OPENSSL_STACK {
    _unused: c_void,
}

#[allow(non_camel_case_types)]
#[repr(transparent)]
struct X509 {
    _unused: c_void,
}

#[repr(C)]
#[allow(non_camel_case_types)]
pub(super) struct SSL_QUIC_METHOD {
    set_encryption_secrets: Option<
        extern fn(
            ssl: *mut SSL,
            level: crypto::Level,
            read_secret: *const u8,
            write_secret: *const u8,
            secret_len: usize,
        ) -> c_int,
    >,

    add_handshake_data: Option<
        unsafe extern fn(
            ssl: *mut SSL,
            level: crypto::Level,
            data: *const u8,
            len: usize,
        ) -> c_int,
    >,

    flush_flight: Option<extern fn(ssl: *mut SSL) -> c_int>,

    send_alert: Option<
        extern fn(ssl: *mut SSL, level: crypto::Level, alert: u8) -> c_int,
    >,
}

pub(super) static QUICHE_STREAM_METHOD: SSL_QUIC_METHOD = SSL_QUIC_METHOD {
    set_encryption_secrets: Some(set_encryption_secrets),
    add_handshake_data: Some(super::add_handshake_data),
    flush_flight: Some(super::flush_flight),
    send_alert: Some(super::send_alert),
};

impl Context {
    pub fn set_early_data_enabled(&mut self, _enabled: bool) {
        // not yet supported
    }
}

impl Handshake {
    pub fn set_quic_early_data_context(&mut self, _context: &[u8]) -> Result<()> {
        // not supported for now.
        map_result(1)
    }

    pub fn curve(&self) -> Option<String> {
        let curve = unsafe {
            let curve_id = SSL_get_negotiated_group(self.as_ptr());
            if curve_id == 0 {
                return None;
            }

            let curve_name = SSL_group_to_name(self.as_ptr(), curve_id);

            match ffi::CStr::from_ptr(curve_name).to_str() {
                Ok(v) => v,

                Err(_) => return None,
            }
        };

        Some(curve.to_string())
    }

    pub fn peer_cert_chain(&self) -> Option<Vec<&[u8]>> {
        // If ssl is server then the leaf will not be included,
        // SSL_get0_peer_certificate should be called.
        let cert_chain = unsafe {
            let chain =
                map_result_ptr(SSL_get_peer_cert_chain(self.as_ptr())).ok()?;

            let num = sk_X509_num(chain);
            if num == 0 {
                return None;
            }

            let mut cert_chain = vec![];
            for i in 0..num {
                let cert =
                    map_result_ptr(sk_X509_value(chain, i) as *mut X509).ok()?;

                let mut out: *mut u8 = std::ptr::null_mut();
                let len = i2d_X509(cert, &mut out);
                if len < 0 {
                    return None;
                }
                cert_chain.push(slice::from_raw_parts(out, len as usize));
            }

            cert_chain
        };

        Some(cert_chain)
    }

    pub fn peer_cert(&self) -> Option<&[u8]> {
        let peer_cert = unsafe {
            // Important: Unit tests is disabled on this method.
            // Although the client calls SSL_CTX_set_verify,  for some reason
            // SSL_get0_peer_certificate seems not to return the peer's
            // certificate as in bssl. SSL_peer_certificate does
            // returns the object representing a certificate used as
            // the local peer's identity.
            let cert =
                map_result_ptr(SSL_get0_peer_certificate(self.as_ptr())).ok()?;
            let mut out: *mut u8 = std::ptr::null_mut();
            let len = i2d_X509(cert, &mut out);
            if len < 0 {
                return None;
            }
            slice::from_raw_parts(out, len as usize)
        };
        Some(peer_cert)
    }

    #[cfg(test)]
    #[allow(dead_code)] // for now, till we implement this using openssl
    pub fn set_failing_private_key_method(&mut self) {}

    pub fn is_in_early_data(&self) -> bool {
        false
    }

    pub fn set_session(&mut self, session: &[u8]) -> Result<()> {
        unsafe {
            let ctx = SSL_get_SSL_CTX(self.as_ptr());

            if ctx.is_null() {
                return Err(Error::TlsFail);
            }

            let session = d2i_SSL_SESSION(
                std::ptr::null_mut(),
                &mut session.as_ptr(),
                session.len() as c_long,
            );

            if session.is_null() {
                return Err(Error::TlsFail);
            }

            let rc = SSL_set_session(self.as_mut_ptr(), session);
            SSL_SESSION_free(session);

            map_result(rc)
        }
    }

    pub fn reset_early_data_reject(&mut self) {
        // not yet supported
    }

    pub fn sigalg(&self) -> Option<String> {
        let sigalg = "";

        Some(sigalg.to_string())
    }
}

extern fn set_encryption_secrets(
    ssl: *mut SSL, level: crypto::Level, read_secret: *const u8,
    write_secret: *const u8, secret_len: usize,
) -> c_int {
    let cipher = map_result_ptr(unsafe { SSL_get_current_cipher(ssl) });
    let _write_ret =
        set_write_secret(ssl, level, cipher.unwrap(), write_secret, secret_len);
    let _read_ret =
        set_read_secret(ssl, level, cipher.unwrap(), read_secret, secret_len);

    1
}

// OpenSSL compatibility functions.
//
// These don't 100% follow the OpenSSL API (e.g. some arguments have slightly
// different types) in order to make them compatible with the BoringSSL API.

#[allow(non_snake_case)]
unsafe fn sk_X509_num(stack: *const STACK_OF) -> usize {
    OPENSSL_sk_num(stack as *const OPENSSL_STACK)
}

#[allow(non_snake_case)]
unsafe fn sk_X509_value(stack: *const STACK_OF, idx: usize) -> *mut c_void {
    OPENSSL_sk_value(stack as *const OPENSSL_STACK, idx)
}

#[allow(non_snake_case)]
pub(super) unsafe fn SSL_CTX_set_session_cache_mode(
    ctx: *mut SSL_CTX, mode: c_int,
) -> c_int {
    const SSL_CTRL_SET_SESS_CACHE_MODE: c_int = 44;

    SSL_CTX_ctrl(
        ctx,
        SSL_CTRL_SET_SESS_CACHE_MODE,
        mode as c_long,
        ptr::null_mut(),
    ) as c_int
}

#[allow(non_snake_case)]
pub(super) unsafe fn SSL_CTX_set_tlsext_ticket_keys(
    ctx: *mut SSL_CTX, key: *const u8, key_len: usize,
) -> c_int {
    const SSL_CTRL_SET_TLSEXT_TICKET_KEYS: c_int = 59;

    SSL_CTX_ctrl(
        ctx,
        SSL_CTRL_SET_TLSEXT_TICKET_KEYS,
        key_len as c_long,
        key as *mut c_void,
    ) as c_int
}

#[allow(non_snake_case)]
pub(super) unsafe fn SSL_set_min_proto_version(
    s: *mut SSL, version: u16,
) -> c_int {
    const SSL_CTRL_SET_MIN_PROTO_VERSION: c_int = 123;

    SSL_ctrl(
        s,
        SSL_CTRL_SET_MIN_PROTO_VERSION,
        version as c_long,
        ptr::null_mut(),
    ) as c_int
}

#[allow(non_snake_case)]
pub(super) unsafe fn SSL_set_max_proto_version(
    s: *mut SSL, version: u16,
) -> c_int {
    const SSL_CTRL_SET_MAX_PROTO_VERSION: c_int = 124;

    SSL_ctrl(
        s,
        SSL_CTRL_SET_MAX_PROTO_VERSION,
        version as c_long,
        ptr::null_mut(),
    ) as c_int
}

#[allow(non_snake_case)]
pub(super) unsafe fn SSL_set_tlsext_host_name(
    s: *mut SSL, name: *const c_char,
) -> c_int {
    const SSL_CTRL_SET_TLSEXT_HOSTNAME: c_int = 55;

    #[allow(non_upper_case_globals)]
    const TLSEXT_NAMETYPE_host_name: c_long = 0;

    SSL_ctrl(
        s,
        SSL_CTRL_SET_TLSEXT_HOSTNAME,
        TLSEXT_NAMETYPE_host_name,
        name as *mut c_void,
    ) as c_int
}

#[allow(non_snake_case)]
pub(super) unsafe fn SSL_get_ex_new_index(
    argl: c_long, argp: *const c_void, newf: *const c_void, dupf: *const c_void,
    freef: *const c_void,
) -> c_int {
    const CRYPTO_EX_INDEX_SSL: c_int = 0;

    CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_SSL, argl, argp, newf, dupf, freef)
}

#[allow(non_snake_case)]
unsafe fn SSL_get_negotiated_group(ssl: *const SSL) -> c_int {
    const SSL_CTRL_GET_NEGOTIATED_GROUP: c_int = 134;
    SSL_ctrl(
        ssl,
        SSL_CTRL_GET_NEGOTIATED_GROUP,
        0 as c_long,
        ptr::null_mut(),
    ) as c_int
}

pub(super) fn get_session_bytes(session: *mut SSL_SESSION) -> Result<Vec<u8>> {
    let session_bytes = unsafe {
        // get session encoding length
        let out_len = i2d_SSL_SESSION(session, std::ptr::null_mut());
        if out_len == 0 {
            return Err(Error::TlsFail);
        }
        let mut out: Vec<c_uchar> = Vec::with_capacity(out_len as usize);

        let out_len = i2d_SSL_SESSION(session, &mut out.as_mut_ptr());
        let session_bytes =
            std::slice::from_raw_parts(out.as_mut_ptr(), out_len as usize)
                .to_vec();
        session_bytes
    };

    Ok(session_bytes)
}
pub(super) const TLS_ERROR: c_int = 2;

extern {

    fn SSL_CTX_ctrl(
        ctx: *mut SSL_CTX, cmd: c_int, larg: c_long, parg: *mut c_void,
    ) -> c_long;

    fn SSL_get_peer_cert_chain(ssl: *const SSL) -> *mut STACK_OF;

    fn SSL_get0_peer_certificate(ssl: *const SSL) -> *mut X509;

    fn SSL_ctrl(
        ssl: *const SSL, cmd: c_int, larg: c_long, parg: *mut c_void,
    ) -> c_long;

    fn i2d_X509(px: *const X509, out: *mut *mut c_uchar) -> c_int;

    fn OPENSSL_sk_num(stack: *const OPENSSL_STACK) -> usize;

    fn OPENSSL_sk_value(stack: *const OPENSSL_STACK, idx: usize) -> *mut c_void;

    // CRYPTO

    fn CRYPTO_get_ex_new_index(
        class_index: c_int, argl: c_long, argp: *const c_void,
        new_func: *const c_void, dup_func: *const c_void,
        free_func: *const c_void,
    ) -> c_int;

    fn d2i_SSL_SESSION(
        a: *mut *mut SSL_SESSION, pp: *mut *const c_uchar, len: c_long,
    ) -> *mut SSL_SESSION;

    pub(super) fn i2d_SSL_SESSION(
        in_: *mut SSL_SESSION, pp: *mut *mut c_uchar,
    ) -> c_int;

    fn SSL_group_to_name(ssl: *const SSL, id: c_int) -> *const c_char;
}
