// Copyright (C) 2018-2019, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use std::ffi;
use std::ptr;
use std::slice;

use std::io::Write;

use libc::c_char;
use libc::c_int;
use libc::c_long;
use libc::c_uint;
use libc::c_void;

use crate::Error;
use crate::Result;

use crate::Connection;
use crate::ConnectionError;

use crate::crypto;
use crate::packet;

const TLS1_3_VERSION: u16 = 0x0304;
const TLS_ALERT_ERROR: u64 = 0x100;
const INTERNAL_ERROR: u64 = 0x01;

#[allow(non_camel_case_types)]
#[repr(transparent)]
struct SSL_METHOD(c_void);

#[allow(non_camel_case_types)]
#[repr(transparent)]
struct SSL_CTX(c_void);

#[allow(non_camel_case_types)]
#[repr(transparent)]
struct SSL(c_void);

#[allow(non_camel_case_types)]
#[repr(transparent)]
struct SSL_CIPHER(c_void);

#[allow(non_camel_case_types)]
#[repr(transparent)]
struct SSL_SESSION(c_void);

#[allow(non_camel_case_types)]
#[repr(transparent)]
struct X509_VERIFY_PARAM(c_void);

#[allow(non_camel_case_types)]
#[repr(transparent)]
#[cfg(windows)]
struct X509_STORE(c_void);

#[allow(non_camel_case_types)]
#[repr(transparent)]
#[cfg(windows)]
struct X509(c_void);

#[allow(non_camel_case_types)]
#[repr(transparent)]
struct STACK_OF(c_void);

#[allow(non_camel_case_types)]
#[repr(transparent)]
struct CRYPTO_BUFFER(c_void);

#[repr(C)]
#[allow(non_camel_case_types)]
struct SSL_QUIC_METHOD {
    set_read_secret: extern fn(
        ssl: *mut SSL,
        level: crypto::Level,
        cipher: *const SSL_CIPHER,
        secret: *const u8,
        secret_len: usize,
    ) -> c_int,

    set_write_secret: extern fn(
        ssl: *mut SSL,
        level: crypto::Level,
        cipher: *const SSL_CIPHER,
        secret: *const u8,
        secret_len: usize,
    ) -> c_int,

    add_handshake_data: extern fn(
        ssl: *mut SSL,
        level: crypto::Level,
        data: *const u8,
        len: usize,
    ) -> c_int,

    flush_flight: extern fn(ssl: *mut SSL) -> c_int,

    send_alert:
        extern fn(ssl: *mut SSL, level: crypto::Level, alert: u8) -> c_int,
}

lazy_static::lazy_static! {
    /// BoringSSL Extra Data Index for Quiche Connections
    pub static ref QUICHE_EX_DATA_INDEX: c_int = unsafe {
        SSL_get_ex_new_index(0, ptr::null(), ptr::null(), ptr::null(), ptr::null())
    };
}

static QUICHE_STREAM_METHOD: SSL_QUIC_METHOD = SSL_QUIC_METHOD {
    set_read_secret,
    set_write_secret,
    add_handshake_data,
    flush_flight,
    send_alert,
};

pub struct Context(*mut SSL_CTX);

impl Context {
    pub fn new() -> Result<Context> {
        unsafe {
            let ctx_raw = SSL_CTX_new(TLS_method());

            let mut ctx = Context(ctx_raw);

            ctx.set_session_callback();

            ctx.load_ca_certs()?;

            Ok(ctx)
        }
    }

    #[cfg(feature = "boringssl-boring-crate")]
    pub fn from_boring(ssl_ctx: boring::ssl::SslContext) -> Context {
        use foreign_types_shared::ForeignType;

        let mut ctx = Context(ssl_ctx.into_ptr() as _);
        ctx.set_session_callback();

        ctx
    }

    pub fn new_handshake(&mut self) -> Result<Handshake> {
        unsafe {
            let ssl = SSL_new(self.as_mut_ptr());
            Ok(Handshake::new(ssl))
        }
    }

    pub fn load_verify_locations_from_file(&mut self, file: &str) -> Result<()> {
        let file = ffi::CString::new(file).map_err(|_| Error::TlsFail)?;
        map_result(unsafe {
            SSL_CTX_load_verify_locations(
                self.as_mut_ptr(),
                file.as_ptr(),
                std::ptr::null(),
            )
        })
    }

    pub fn load_verify_locations_from_directory(
        &mut self, path: &str,
    ) -> Result<()> {
        let path = ffi::CString::new(path).map_err(|_| Error::TlsFail)?;
        map_result(unsafe {
            SSL_CTX_load_verify_locations(
                self.as_mut_ptr(),
                std::ptr::null(),
                path.as_ptr(),
            )
        })
    }

    pub fn use_certificate_chain_file(&mut self, file: &str) -> Result<()> {
        let cstr = ffi::CString::new(file).map_err(|_| Error::TlsFail)?;
        map_result(unsafe {
            SSL_CTX_use_certificate_chain_file(self.as_mut_ptr(), cstr.as_ptr())
        })
    }

    pub fn use_privkey_file(&mut self, file: &str) -> Result<()> {
        let cstr = ffi::CString::new(file).map_err(|_| Error::TlsFail)?;
        map_result(unsafe {
            SSL_CTX_use_PrivateKey_file(self.as_mut_ptr(), cstr.as_ptr(), 1)
        })
    }

    #[cfg(not(windows))]
    fn load_ca_certs(&mut self) -> Result<()> {
        unsafe { map_result(SSL_CTX_set_default_verify_paths(self.as_mut_ptr())) }
    }

    #[cfg(windows)]
    fn load_ca_certs(&mut self) -> Result<()> {
        unsafe {
            let cstr = ffi::CString::new("Root").map_err(|_| Error::TlsFail)?;
            let sys_store = winapi::um::wincrypt::CertOpenSystemStoreA(
                0,
                cstr.as_ptr() as winapi::um::winnt::LPCSTR,
            );
            if sys_store.is_null() {
                return Err(Error::TlsFail);
            }

            let ctx_store = SSL_CTX_get_cert_store(self.as_mut_ptr());
            if ctx_store.is_null() {
                return Err(Error::TlsFail);
            }

            let mut ctx_p = winapi::um::wincrypt::CertEnumCertificatesInStore(
                sys_store,
                ptr::null(),
            );

            while !ctx_p.is_null() {
                let in_p = (*ctx_p).pbCertEncoded as *const u8;

                let cert = d2i_X509(
                    ptr::null_mut(),
                    &in_p,
                    (*ctx_p).cbCertEncoded as i32,
                );
                if !cert.is_null() {
                    X509_STORE_add_cert(ctx_store, cert);
                }

                X509_free(cert);

                ctx_p = winapi::um::wincrypt::CertEnumCertificatesInStore(
                    sys_store, ctx_p,
                );
            }

            // tidy up
            winapi::um::wincrypt::CertFreeCertificateContext(ctx_p);
            winapi::um::wincrypt::CertCloseStore(sys_store, 0);
        }

        Ok(())
    }

    fn set_session_callback(&mut self) {
        unsafe {
            // This is needed to enable the session callback on the client. On
            // the server it doesn't do anything.
            SSL_CTX_set_session_cache_mode(
                self.as_mut_ptr(),
                0x0001, // SSL_SESS_CACHE_CLIENT
            );

            SSL_CTX_sess_set_new_cb(self.as_mut_ptr(), new_session);
        };
    }

    pub fn set_verify(&mut self, verify: bool) {
        let mode = if verify {
            0x01 // SSL_VERIFY_PEER
        } else {
            0x00 // SSL_VERIFY_NONE
        };

        unsafe {
            SSL_CTX_set_verify(self.as_mut_ptr(), mode, ptr::null());
        }
    }

    pub fn enable_keylog(&mut self) {
        unsafe {
            SSL_CTX_set_keylog_callback(self.as_mut_ptr(), keylog);
        }
    }

    pub fn set_alpn(&mut self, v: &[&[u8]]) -> Result<()> {
        let mut protos: Vec<u8> = Vec::new();

        for proto in v {
            protos.push(proto.len() as u8);
            protos.extend_from_slice(proto);
        }

        // Configure ALPN for servers.
        unsafe {
            SSL_CTX_set_alpn_select_cb(
                self.as_mut_ptr(),
                select_alpn,
                ptr::null_mut(),
            );
        }

        // Configure ALPN for clients.
        map_result_zero_is_success(unsafe {
            SSL_CTX_set_alpn_protos(
                self.as_mut_ptr(),
                protos.as_ptr(),
                protos.len(),
            )
        })
    }

    pub fn set_ticket_key(&mut self, key: &[u8]) -> Result<()> {
        map_result(unsafe {
            SSL_CTX_set_tlsext_ticket_keys(
                self.as_mut_ptr(),
                key.as_ptr(),
                key.len(),
            )
        })
    }

    pub fn set_early_data_enabled(&mut self, enabled: bool) {
        let enabled = if enabled { 1 } else { 0 };

        unsafe {
            SSL_CTX_set_early_data_enabled(self.as_mut_ptr(), enabled);
        }
    }

    fn as_mut_ptr(&mut self) -> *mut SSL_CTX {
        self.0
    }
}

// NOTE: These traits are not automatically implemented for Context due to the
// raw pointer it wraps. However, the underlying data is not aliased (as Context
// should be its only owner), and there is no interior mutability, as the
// pointer is not accessed directly outside of this module, and the Context
// object API should preserve Rust's borrowing guarantees.
unsafe impl std::marker::Send for Context {}
unsafe impl std::marker::Sync for Context {}

impl Drop for Context {
    fn drop(&mut self) {
        unsafe { SSL_CTX_free(self.as_mut_ptr()) }
    }
}

pub struct Handshake {
    /// Raw pointer
    ptr: *mut SSL,
    /// SSL_process_quic_post_handshake should be called when whenever
    /// SSL_provide_quic_data is called to process the provided data.
    provided_data_outstanding: bool,
}

impl Handshake {
    #[cfg(feature = "ffi")]
    pub unsafe fn from_ptr(ssl: *mut c_void) -> Handshake {
        Handshake::new(ssl as *mut SSL)
    }

    fn new(ptr: *mut SSL) -> Handshake {
        Handshake {
            ptr,
            provided_data_outstanding: false,
        }
    }

    pub fn get_error(&self, ret_code: c_int) -> c_int {
        unsafe { SSL_get_error(self.as_ptr(), ret_code) }
    }

    pub fn init(&mut self, is_server: bool) -> Result<()> {
        self.set_state(is_server);

        self.set_min_proto_version(TLS1_3_VERSION);
        self.set_max_proto_version(TLS1_3_VERSION);

        self.set_quic_method()?;

        // TODO: the early data context should include transport parameters and
        // HTTP/3 SETTINGS in wire format.
        self.set_quic_early_data_context(b"quiche")?;

        self.set_quiet_shutdown(true);

        Ok(())
    }

    pub fn use_legacy_codepoint(&mut self, use_legacy: bool) {
        unsafe {
            SSL_set_quic_use_legacy_codepoint(
                self.as_mut_ptr(),
                use_legacy as c_int,
            );
        }
    }

    pub fn set_state(&mut self, is_server: bool) {
        unsafe {
            if is_server {
                SSL_set_accept_state(self.as_mut_ptr());
            } else {
                SSL_set_connect_state(self.as_mut_ptr());
            }
        }
    }

    pub fn set_ex_data<T>(&mut self, idx: c_int, data: *const T) -> Result<()> {
        map_result(unsafe {
            let ptr = data as *const c_void;
            SSL_set_ex_data(self.as_mut_ptr(), idx, ptr)
        })
    }

    pub fn set_quic_method(&mut self) -> Result<()> {
        map_result(unsafe {
            SSL_set_quic_method(self.as_mut_ptr(), &QUICHE_STREAM_METHOD)
        })
    }

    pub fn set_quic_early_data_context(&mut self, context: &[u8]) -> Result<()> {
        map_result(unsafe {
            SSL_set_quic_early_data_context(
                self.as_mut_ptr(),
                context.as_ptr(),
                context.len(),
            )
        })
    }

    pub fn set_min_proto_version(&mut self, version: u16) {
        unsafe { SSL_set_min_proto_version(self.as_mut_ptr(), version) }
    }

    pub fn set_max_proto_version(&mut self, version: u16) {
        unsafe { SSL_set_max_proto_version(self.as_mut_ptr(), version) }
    }

    pub fn set_quiet_shutdown(&mut self, mode: bool) {
        unsafe {
            SSL_set_quiet_shutdown(self.as_mut_ptr(), if mode { 1 } else { 0 })
        }
    }

    pub fn set_host_name(&mut self, name: &str) -> Result<()> {
        let cstr = ffi::CString::new(name).map_err(|_| Error::TlsFail)?;
        let rc =
            unsafe { SSL_set_tlsext_host_name(self.as_mut_ptr(), cstr.as_ptr()) };
        self.map_result_ssl(rc)?;

        let param = unsafe { SSL_get0_param(self.as_mut_ptr()) };

        map_result(unsafe {
            X509_VERIFY_PARAM_set1_host(param, cstr.as_ptr(), name.len())
        })
    }

    pub fn set_quic_transport_params(&mut self, buf: &[u8]) -> Result<()> {
        let rc = unsafe {
            SSL_set_quic_transport_params(
                self.as_mut_ptr(),
                buf.as_ptr(),
                buf.len(),
            )
        };
        self.map_result_ssl(rc)
    }

    #[cfg(test)]
    pub fn set_options(&mut self, opts: u32) {
        unsafe {
            SSL_set_options(self.as_mut_ptr(), opts);
        }
    }

    pub fn quic_transport_params(&self) -> &[u8] {
        let mut ptr: *const u8 = ptr::null();
        let mut len: usize = 0;

        unsafe {
            SSL_get_peer_quic_transport_params(self.as_ptr(), &mut ptr, &mut len);
        }

        if len == 0 {
            return &mut [];
        }

        unsafe { slice::from_raw_parts(ptr, len) }
    }

    pub fn alpn_protocol(&self) -> &[u8] {
        let mut ptr: *const u8 = ptr::null();
        let mut len: u32 = 0;

        unsafe {
            SSL_get0_alpn_selected(self.as_ptr(), &mut ptr, &mut len);
        }

        if len == 0 {
            return &mut [];
        }

        unsafe { slice::from_raw_parts(ptr, len as usize) }
    }

    pub fn server_name(&self) -> Option<&str> {
        let s = unsafe {
            let ptr = SSL_get_servername(
                self.as_ptr(),
                0, // TLSEXT_NAMETYPE_host_name
            );

            if ptr.is_null() {
                return None;
            }

            ffi::CStr::from_ptr(ptr)
        };

        s.to_str().ok()
    }

    pub fn set_session(&mut self, session: &[u8]) -> Result<()> {
        unsafe {
            let ctx = SSL_get_SSL_CTX(self.as_ptr());

            if ctx.is_null() {
                return Err(Error::TlsFail);
            }

            let session =
                SSL_SESSION_from_bytes(session.as_ptr(), session.len(), ctx);

            if session.is_null() {
                return Err(Error::TlsFail);
            }

            let rc = SSL_set_session(self.as_mut_ptr(), session);
            SSL_SESSION_free(session);

            map_result(rc)
        }
    }

    pub fn provide_data(
        &mut self, level: crypto::Level, buf: &[u8],
    ) -> Result<()> {
        self.provided_data_outstanding = true;
        let rc = unsafe {
            SSL_provide_quic_data(
                self.as_mut_ptr(),
                level,
                buf.as_ptr(),
                buf.len(),
            )
        };
        self.map_result_ssl(rc)
    }

    pub fn do_handshake(&mut self, ex_data: &mut ExData) -> Result<()> {
        self.set_ex_data(*QUICHE_EX_DATA_INDEX, ex_data)?;
        let rc = unsafe { SSL_do_handshake(self.as_mut_ptr()) };
        self.set_ex_data::<Connection>(*QUICHE_EX_DATA_INDEX, std::ptr::null())?;

        self.set_transport_error(ex_data, rc);
        self.map_result_ssl(rc)
    }

    pub fn process_post_handshake(&mut self, ex_data: &mut ExData) -> Result<()> {
        // If SSL_provide_quic_data hasn't been called since we last called
        // SSL_process_quic_post_handshake, then there's nothing to do.
        if !self.provided_data_outstanding {
            return Ok(());
        }
        self.provided_data_outstanding = false;

        self.set_ex_data(*QUICHE_EX_DATA_INDEX, ex_data)?;
        let rc = unsafe { SSL_process_quic_post_handshake(self.as_mut_ptr()) };
        self.set_ex_data::<Connection>(*QUICHE_EX_DATA_INDEX, std::ptr::null())?;

        self.set_transport_error(ex_data, rc);
        self.map_result_ssl(rc)
    }

    pub fn reset_early_data_reject(&mut self) {
        unsafe { SSL_reset_early_data_reject(self.as_mut_ptr()) };
    }

    pub fn write_level(&self) -> crypto::Level {
        unsafe { SSL_quic_write_level(self.as_ptr()) }
    }

    pub fn cipher(&self) -> Option<crypto::Algorithm> {
        let cipher =
            map_result_ptr(unsafe { SSL_get_current_cipher(self.as_ptr()) });

        get_cipher_from_ptr(cipher.ok()?).ok()
    }

    pub fn curve(&self) -> Option<String> {
        let curve = unsafe {
            let curve_id = SSL_get_curve_id(self.as_ptr());
            if curve_id == 0 {
                return None;
            }

            let curve_name = SSL_get_curve_name(curve_id);
            match ffi::CStr::from_ptr(curve_name).to_str() {
                Ok(v) => v,

                Err(_) => return None,
            }
        };

        Some(curve.to_string())
    }

    pub fn sigalg(&self) -> Option<String> {
        let sigalg = unsafe {
            let sigalg_id = SSL_get_peer_signature_algorithm(self.as_ptr());
            if sigalg_id == 0 {
                return None;
            }

            let sigalg_name = SSL_get_signature_algorithm_name(sigalg_id, 1);
            match ffi::CStr::from_ptr(sigalg_name).to_str() {
                Ok(v) => v,

                Err(_) => return None,
            }
        };

        Some(sigalg.to_string())
    }

    pub fn peer_cert_chain(&self) -> Option<Vec<&[u8]>> {
        let cert_chain = unsafe {
            let chain =
                map_result_ptr(SSL_get0_peer_certificates(self.as_ptr())).ok()?;

            let num = sk_num(chain);
            if num <= 0 {
                return None;
            }

            let mut cert_chain = vec![];
            for i in 0..num {
                let buffer =
                    map_result_ptr(sk_value(chain, i) as *const CRYPTO_BUFFER)
                        .ok()?;

                let out_len = CRYPTO_BUFFER_len(buffer);
                if out_len == 0 {
                    return None;
                }

                let out = CRYPTO_BUFFER_data(buffer);
                let slice = slice::from_raw_parts(out, out_len as usize);

                cert_chain.push(slice);
            }

            cert_chain
        };

        Some(cert_chain)
    }

    pub fn peer_cert(&self) -> Option<&[u8]> {
        let peer_cert = unsafe {
            let chain =
                map_result_ptr(SSL_get0_peer_certificates(self.as_ptr())).ok()?;
            if sk_num(chain) <= 0 {
                return None;
            }

            let buffer =
                map_result_ptr(sk_value(chain, 0) as *const CRYPTO_BUFFER)
                    .ok()?;

            let out_len = CRYPTO_BUFFER_len(buffer);
            if out_len == 0 {
                return None;
            }

            let out = CRYPTO_BUFFER_data(buffer);
            slice::from_raw_parts(out, out_len as usize)
        };

        Some(peer_cert)
    }

    pub fn is_completed(&self) -> bool {
        unsafe { SSL_in_init(self.as_ptr()) == 0 }
    }

    pub fn is_resumed(&self) -> bool {
        unsafe { SSL_session_reused(self.as_ptr()) == 1 }
    }

    pub fn is_in_early_data(&self) -> bool {
        unsafe { SSL_in_early_data(self.as_ptr()) == 1 }
    }

    pub fn clear(&mut self) -> Result<()> {
        let rc = unsafe { SSL_clear(self.as_mut_ptr()) };
        self.map_result_ssl(rc)
    }

    fn as_ptr(&self) -> *const SSL {
        self.ptr
    }

    fn as_mut_ptr(&mut self) -> *mut SSL {
        self.ptr
    }

    fn map_result_ssl(&mut self, bssl_result: c_int) -> Result<()> {
        match bssl_result {
            1 => Ok(()),

            _ => {
                let ssl_err = self.get_error(bssl_result);
                match ssl_err {
                    // SSL_ERROR_SSL
                    1 => {
                        log_ssl_error();

                        Err(Error::TlsFail)
                    },

                    // SSL_ERROR_WANT_READ
                    2 => Err(Error::Done),

                    // SSL_ERROR_WANT_WRITE
                    3 => Err(Error::Done),

                    // SSL_ERROR_WANT_X509_LOOKUP
                    4 => Err(Error::Done),

                    // SSL_ERROR_SYSCALL
                    5 => Err(Error::TlsFail),

                    // SSL_ERROR_PENDING_SESSION
                    11 => Err(Error::Done),

                    // SSL_ERROR_PENDING_CERTIFICATE
                    12 => Err(Error::Done),

                    // SSL_ERROR_WANT_PRIVATE_KEY_OPERATION
                    13 => Err(Error::Done),

                    // SSL_ERROR_PENDING_TICKET
                    14 => Err(Error::Done),

                    // SSL_ERROR_EARLY_DATA_REJECTED
                    15 => {
                        self.reset_early_data_reject();
                        Err(Error::Done)
                    },

                    // SSL_ERROR_WANT_CERTIFICATE_VERIFY
                    16 => Err(Error::Done),

                    _ => Err(Error::TlsFail),
                }
            },
        }
    }

    fn set_transport_error(&mut self, ex_data: &mut ExData, bssl_result: c_int) {
        // SSL_ERROR_SSL
        if self.get_error(bssl_result) == 1 {
            // SSL_ERROR_SSL can't be recovered so ensure we set a
            // local_error so the connection is closed.
            // See https://www.openssl.org/docs/man1.1.1/man3/SSL_get_error.html
            if ex_data.local_error.is_none() {
                *ex_data.local_error = Some(ConnectionError {
                    is_app: false,
                    error_code: INTERNAL_ERROR,
                    reason: Vec::new(),
                })
            }
        }
    }
}

// NOTE: These traits are not automatically implemented for Handshake due to the
// raw pointer it wraps. However, the underlying data is not aliased (as
// Handshake should be its only owner), and there is no interior mutability, as
// the pointer is not accessed directly outside of this module, and the
// Handshake object API should preserve Rust's borrowing guarantees.
unsafe impl std::marker::Send for Handshake {}
unsafe impl std::marker::Sync for Handshake {}

impl Drop for Handshake {
    fn drop(&mut self) {
        unsafe { SSL_free(self.as_mut_ptr()) }
    }
}

pub struct ExData<'a> {
    pub application_protos: &'a Vec<Vec<u8>>,

    pub pkt_num_spaces: &'a mut [packet::PktNumSpace; packet::EPOCH_COUNT],

    pub session: &'a mut Option<Vec<u8>>,

    pub local_error: &'a mut Option<super::ConnectionError>,

    pub keylog: Option<&'a mut Box<dyn std::io::Write + Send + Sync>>,

    pub trace_id: &'a str,

    pub is_server: bool,
}

fn get_ex_data_from_ptr<'a, T>(ptr: *mut SSL, idx: c_int) -> Option<&'a mut T> {
    unsafe {
        let data = SSL_get_ex_data(ptr, idx) as *mut T;
        data.as_mut()
    }
}

fn get_cipher_from_ptr(cipher: *const SSL_CIPHER) -> Result<crypto::Algorithm> {
    let cipher_id = unsafe { SSL_CIPHER_get_id(cipher) };

    let alg = match cipher_id {
        0x0300_1301 => crypto::Algorithm::AES128_GCM,
        0x0300_1302 => crypto::Algorithm::AES256_GCM,
        0x0300_1303 => crypto::Algorithm::ChaCha20_Poly1305,
        _ => return Err(Error::TlsFail),
    };

    Ok(alg)
}

extern fn set_read_secret(
    ssl: *mut SSL, level: crypto::Level, cipher: *const SSL_CIPHER,
    secret: *const u8, secret_len: usize,
) -> c_int {
    let ex_data = match get_ex_data_from_ptr::<ExData>(ssl, *QUICHE_EX_DATA_INDEX)
    {
        Some(v) => v,

        None => return 0,
    };

    trace!("{} set read secret lvl={:?}", ex_data.trace_id, level);

    let space = match level {
        crypto::Level::Initial =>
            &mut ex_data.pkt_num_spaces[packet::EPOCH_INITIAL],
        crypto::Level::ZeroRTT =>
            &mut ex_data.pkt_num_spaces[packet::EPOCH_APPLICATION],
        crypto::Level::Handshake =>
            &mut ex_data.pkt_num_spaces[packet::EPOCH_HANDSHAKE],
        crypto::Level::OneRTT =>
            &mut ex_data.pkt_num_spaces[packet::EPOCH_APPLICATION],
    };

    let aead = match get_cipher_from_ptr(cipher) {
        Ok(v) => v,

        Err(_) => return 0,
    };

    // 0-RTT read secrets are present only on the server.
    if level != crypto::Level::ZeroRTT || ex_data.is_server {
        let secret = unsafe { slice::from_raw_parts(secret, secret_len) };

        let open = match crypto::Open::from_secret(aead, secret) {
            Ok(v) => v,

            Err(_) => return 0,
        };

        if level == crypto::Level::ZeroRTT {
            space.crypto_0rtt_open = Some(open);
            return 1;
        }

        space.crypto_open = Some(open);
    }

    1
}

extern fn set_write_secret(
    ssl: *mut SSL, level: crypto::Level, cipher: *const SSL_CIPHER,
    secret: *const u8, secret_len: usize,
) -> c_int {
    let ex_data = match get_ex_data_from_ptr::<ExData>(ssl, *QUICHE_EX_DATA_INDEX)
    {
        Some(v) => v,

        None => return 0,
    };

    trace!("{} set write secret lvl={:?}", ex_data.trace_id, level);

    let space = match level {
        crypto::Level::Initial =>
            &mut ex_data.pkt_num_spaces[packet::EPOCH_INITIAL],
        crypto::Level::ZeroRTT =>
            &mut ex_data.pkt_num_spaces[packet::EPOCH_APPLICATION],
        crypto::Level::Handshake =>
            &mut ex_data.pkt_num_spaces[packet::EPOCH_HANDSHAKE],
        crypto::Level::OneRTT =>
            &mut ex_data.pkt_num_spaces[packet::EPOCH_APPLICATION],
    };

    let aead = match get_cipher_from_ptr(cipher) {
        Ok(v) => v,

        Err(_) => return 0,
    };

    // 0-RTT write secrets are present only on the client.
    if level != crypto::Level::ZeroRTT || !ex_data.is_server {
        let secret = unsafe { slice::from_raw_parts(secret, secret_len) };

        let seal = match crypto::Seal::from_secret(aead, secret) {
            Ok(v) => v,

            Err(_) => return 0,
        };

        space.crypto_seal = Some(seal);
    }

    1
}

extern fn add_handshake_data(
    ssl: *mut SSL, level: crypto::Level, data: *const u8, len: usize,
) -> c_int {
    let ex_data = match get_ex_data_from_ptr::<ExData>(ssl, *QUICHE_EX_DATA_INDEX)
    {
        Some(v) => v,

        None => return 0,
    };

    trace!(
        "{} write message lvl={:?} len={}",
        ex_data.trace_id,
        level,
        len
    );

    let buf = unsafe { slice::from_raw_parts(data, len) };

    let space = match level {
        crypto::Level::Initial =>
            &mut ex_data.pkt_num_spaces[packet::EPOCH_INITIAL],
        crypto::Level::ZeroRTT => unreachable!(),
        crypto::Level::Handshake =>
            &mut ex_data.pkt_num_spaces[packet::EPOCH_HANDSHAKE],
        crypto::Level::OneRTT =>
            &mut ex_data.pkt_num_spaces[packet::EPOCH_APPLICATION],
    };

    if space.crypto_stream.send.write(buf, false).is_err() {
        return 0;
    }

    1
}

extern fn flush_flight(_ssl: *mut SSL) -> c_int {
    // We don't really need to anything here since the output packets are
    // generated separately, when conn.send() is called.

    1
}

extern fn send_alert(ssl: *mut SSL, level: crypto::Level, alert: u8) -> c_int {
    let ex_data = match get_ex_data_from_ptr::<ExData>(ssl, *QUICHE_EX_DATA_INDEX)
    {
        Some(v) => v,

        None => return 0,
    };

    trace!(
        "{} send alert lvl={:?} alert={:x}",
        ex_data.trace_id,
        level,
        alert
    );

    let error: u64 = TLS_ALERT_ERROR + u64::from(alert);
    *ex_data.local_error = Some(ConnectionError {
        is_app: false,
        error_code: error,
        reason: Vec::new(),
    });

    1
}

extern fn keylog(ssl: *mut SSL, line: *const c_char) {
    let ex_data = match get_ex_data_from_ptr::<ExData>(ssl, *QUICHE_EX_DATA_INDEX)
    {
        Some(v) => v,

        None => return,
    };

    if let Some(keylog) = &mut ex_data.keylog {
        let data = unsafe { ffi::CStr::from_ptr(line).to_bytes() };

        let mut full_line = Vec::with_capacity(data.len() + 1);
        full_line.extend_from_slice(data);
        full_line.push(b'\n');

        keylog.write_all(&full_line[..]).ok();
    }
}

extern fn select_alpn(
    ssl: *mut SSL, out: *mut *const u8, out_len: *mut u8, inp: *mut u8,
    in_len: c_uint, _arg: *mut c_void,
) -> c_int {
    let ex_data = match get_ex_data_from_ptr::<ExData>(ssl, *QUICHE_EX_DATA_INDEX)
    {
        Some(v) => v,

        None => return 3, // SSL_TLSEXT_ERR_NOACK
    };

    if ex_data.application_protos.is_empty() {
        return 3; // SSL_TLSEXT_ERR_NOACK
    }

    let mut protos = octets::Octets::with_slice(unsafe {
        slice::from_raw_parts(inp, in_len as usize)
    });

    while let Ok(proto) = protos.get_bytes_with_u8_length() {
        let found = ex_data.application_protos.iter().any(|expected| {
            trace!(
                "checking peer ALPN {:?} against {:?}",
                std::str::from_utf8(proto.as_ref()),
                std::str::from_utf8(expected.as_slice())
            );

            if expected.len() == proto.len() &&
                expected.as_slice() == proto.as_ref()
            {
                unsafe {
                    *out = expected.as_slice().as_ptr();
                    *out_len = expected.len() as u8;
                }

                return true;
            }

            false
        });

        if found {
            return 0; // SSL_TLSEXT_ERR_OK
        }
    }

    3 // SSL_TLSEXT_ERR_NOACK
}

extern fn new_session(ssl: *mut SSL, session: *mut SSL_SESSION) -> c_int {
    let ex_data = match get_ex_data_from_ptr::<ExData>(ssl, *QUICHE_EX_DATA_INDEX)
    {
        Some(v) => v,

        None => return 0,
    };

    let handshake = Handshake::new(ssl);
    let peer_params = handshake.quic_transport_params();

    // Serialize session object into buffer.
    let session_bytes = unsafe {
        let mut out: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;

        if SSL_SESSION_to_bytes(session, &mut out, &mut out_len) == 0 {
            return 0;
        }

        let session_bytes = std::slice::from_raw_parts(out, out_len).to_vec();
        OPENSSL_free(out as *mut c_void);

        session_bytes
    };

    let mut buffer =
        Vec::with_capacity(8 + peer_params.len() + 8 + session_bytes.len());

    let session_bytes_len = session_bytes.len() as u64;

    if buffer.write(&session_bytes_len.to_be_bytes()).is_err() {
        std::mem::forget(handshake);
        return 0;
    }

    if buffer.write(&session_bytes).is_err() {
        std::mem::forget(handshake);
        return 0;
    }

    let peer_params_len = peer_params.len() as u64;

    if buffer.write(&peer_params_len.to_be_bytes()).is_err() {
        std::mem::forget(handshake);
        return 0;
    }

    if buffer.write(peer_params).is_err() {
        std::mem::forget(handshake);
        return 0;
    }

    *ex_data.session = Some(buffer);

    // Prevent handshake from being freed, as we still need it.
    std::mem::forget(handshake);

    0
}

fn map_result(bssl_result: c_int) -> Result<()> {
    match bssl_result {
        1 => Ok(()),
        _ => Err(Error::TlsFail),
    }
}

fn map_result_zero_is_success(bssl_result: c_int) -> Result<()> {
    match bssl_result {
        0 => Ok(()),
        _ => Err(Error::TlsFail),
    }
}

fn map_result_ptr<'a, T>(bssl_result: *const T) -> Result<&'a T> {
    match unsafe { bssl_result.as_ref() } {
        Some(v) => Ok(v),
        None => Err(Error::TlsFail),
    }
}

fn log_ssl_error() {
    let err = [0; 1024];

    unsafe {
        let e = ERR_peek_error();
        ERR_error_string_n(e, err.as_ptr(), err.len());
    }

    trace!("{}", std::str::from_utf8(&err).unwrap());
}

extern {
    // SSL_METHOD
    fn TLS_method() -> *const SSL_METHOD;

    // SSL_CTX
    fn SSL_CTX_new(method: *const SSL_METHOD) -> *mut SSL_CTX;
    fn SSL_CTX_free(ctx: *mut SSL_CTX);

    fn SSL_CTX_use_certificate_chain_file(
        ctx: *mut SSL_CTX, file: *const c_char,
    ) -> c_int;

    fn SSL_CTX_use_PrivateKey_file(
        ctx: *mut SSL_CTX, file: *const c_char, ty: c_int,
    ) -> c_int;

    fn SSL_CTX_load_verify_locations(
        ctx: *mut SSL_CTX, file: *const c_char, path: *const c_char,
    ) -> c_int;

    #[cfg(not(windows))]
    fn SSL_CTX_set_default_verify_paths(ctx: *mut SSL_CTX) -> c_int;

    #[cfg(windows)]
    fn SSL_CTX_get_cert_store(ctx: *mut SSL_CTX) -> *mut X509_STORE;

    fn SSL_CTX_set_verify(ctx: *mut SSL_CTX, mode: c_int, cb: *const c_void);

    fn SSL_CTX_set_keylog_callback(
        ctx: *mut SSL_CTX, cb: extern fn(ssl: *mut SSL, line: *const c_char),
    );

    fn SSL_CTX_set_tlsext_ticket_keys(
        ctx: *mut SSL_CTX, key: *const u8, key_len: usize,
    ) -> c_int;

    fn SSL_CTX_set_alpn_protos(
        ctx: *mut SSL_CTX, protos: *const u8, protos_len: usize,
    ) -> c_int;

    fn SSL_CTX_set_alpn_select_cb(
        ctx: *mut SSL_CTX,
        cb: extern fn(
            ssl: *mut SSL,
            out: *mut *const u8,
            out_len: *mut u8,
            inp: *mut u8,
            in_len: c_uint,
            arg: *mut c_void,
        ) -> c_int,
        arg: *mut c_void,
    );

    fn SSL_CTX_set_early_data_enabled(ctx: *mut SSL_CTX, enabled: i32);

    fn SSL_CTX_set_session_cache_mode(ctx: *mut SSL_CTX, mode: c_int) -> c_int;

    fn SSL_CTX_sess_set_new_cb(
        ctx: *mut SSL_CTX,
        cb: extern fn(ssl: *mut SSL, session: *mut SSL_SESSION) -> c_int,
    );

    // SSL
    fn SSL_get_ex_new_index(
        argl: c_long, argp: *const c_void, unused: *const c_void,
        dup_unused: *const c_void, free_func: *const c_void,
    ) -> c_int;

    fn SSL_new(ctx: *mut SSL_CTX) -> *mut SSL;

    fn SSL_get_error(ssl: *const SSL, ret_code: c_int) -> c_int;

    fn SSL_set_accept_state(ssl: *mut SSL);
    fn SSL_set_connect_state(ssl: *mut SSL);

    fn SSL_get0_param(ssl: *mut SSL) -> *mut X509_VERIFY_PARAM;

    fn SSL_set_ex_data(ssl: *mut SSL, idx: c_int, ptr: *const c_void) -> c_int;
    fn SSL_get_ex_data(ssl: *mut SSL, idx: c_int) -> *mut c_void;

    fn SSL_get_current_cipher(ssl: *const SSL) -> *const SSL_CIPHER;

    fn SSL_get_curve_id(ssl: *const SSL) -> u16;
    fn SSL_get_curve_name(curve: u16) -> *const c_char;

    fn SSL_get_peer_signature_algorithm(ssl: *const SSL) -> u16;
    fn SSL_get_signature_algorithm_name(
        sigalg: u16, include_curve: i32,
    ) -> *const c_char;

    fn SSL_set_session(ssl: *mut SSL, session: *mut SSL_SESSION) -> c_int;

    fn SSL_get_SSL_CTX(ssl: *const SSL) -> *mut SSL_CTX;

    fn SSL_get0_peer_certificates(ssl: *const SSL) -> *const STACK_OF;

    fn SSL_set_min_proto_version(ssl: *mut SSL, version: u16);
    fn SSL_set_max_proto_version(ssl: *mut SSL, version: u16);

    fn SSL_set_quiet_shutdown(ssl: *mut SSL, mode: c_int);

    fn SSL_set_tlsext_host_name(ssl: *mut SSL, name: *const c_char) -> c_int;

    fn SSL_set_quic_transport_params(
        ssl: *mut SSL, params: *const u8, params_len: usize,
    ) -> c_int;

    #[cfg(test)]
    fn SSL_set_options(ssl: *mut SSL, opts: u32) -> u32;

    fn SSL_set_quic_method(
        ssl: *mut SSL, quic_method: *const SSL_QUIC_METHOD,
    ) -> c_int;

    fn SSL_set_quic_use_legacy_codepoint(ssl: *mut SSL, use_legacy: c_int);

    fn SSL_set_quic_early_data_context(
        ssl: *mut SSL, context: *const u8, context_len: usize,
    ) -> c_int;

    fn SSL_get_peer_quic_transport_params(
        ssl: *const SSL, out_params: *mut *const u8, out_params_len: *mut usize,
    );

    fn SSL_get0_alpn_selected(
        ssl: *const SSL, out: *mut *const u8, out_len: *mut u32,
    );

    fn SSL_get_servername(ssl: *const SSL, ty: c_int) -> *const c_char;

    fn SSL_provide_quic_data(
        ssl: *mut SSL, level: crypto::Level, data: *const u8, len: usize,
    ) -> c_int;

    fn SSL_process_quic_post_handshake(ssl: *mut SSL) -> c_int;

    fn SSL_reset_early_data_reject(ssl: *mut SSL);

    fn SSL_do_handshake(ssl: *mut SSL) -> c_int;

    fn SSL_quic_write_level(ssl: *const SSL) -> crypto::Level;

    fn SSL_session_reused(ssl: *const SSL) -> c_int;

    fn SSL_in_init(ssl: *const SSL) -> c_int;

    fn SSL_in_early_data(ssl: *const SSL) -> c_int;

    fn SSL_clear(ssl: *mut SSL) -> c_int;

    fn SSL_free(ssl: *mut SSL);

    // SSL_CIPHER
    fn SSL_CIPHER_get_id(cipher: *const SSL_CIPHER) -> c_uint;

    // SSL_SESSION
    fn SSL_SESSION_to_bytes(
        session: *const SSL_SESSION, out: *mut *mut u8, out_len: *mut usize,
    ) -> c_int;

    fn SSL_SESSION_from_bytes(
        input: *const u8, input_len: usize, ctx: *const SSL_CTX,
    ) -> *mut SSL_SESSION;

    fn SSL_SESSION_free(session: *mut SSL_SESSION);

    // X509_VERIFY_PARAM
    fn X509_VERIFY_PARAM_set1_host(
        param: *mut X509_VERIFY_PARAM, name: *const c_char, namelen: usize,
    ) -> c_int;

    // X509_STORE
    #[cfg(windows)]
    fn X509_STORE_add_cert(ctx: *mut X509_STORE, x: *mut X509) -> c_int;

    // X509
    #[cfg(windows)]
    fn X509_free(x: *mut X509);
    #[cfg(windows)]
    fn d2i_X509(px: *mut X509, input: *const *const u8, len: c_int) -> *mut X509;

    // STACK_OF
    fn sk_num(stack: *const STACK_OF) -> c_int;
    fn sk_value(stack: *const STACK_OF, idx: c_int) -> *mut c_void;

    // CRYPTO_BUFFER
    fn CRYPTO_BUFFER_len(buffer: *const CRYPTO_BUFFER) -> usize;
    fn CRYPTO_BUFFER_data(buffer: *const CRYPTO_BUFFER) -> *const u8;

    // ERR
    fn ERR_peek_error() -> c_uint;

    fn ERR_error_string_n(err: c_uint, buf: *const u8, len: usize);

    // OPENSSL
    fn OPENSSL_free(ptr: *mut c_void);
}
