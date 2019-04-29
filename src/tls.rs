// Copyright (C) 2018, Cloudflare, Inc.
// Copyright (C) 2018, Alessandro Ghedini
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

use std::io::prelude::*;

use libc::c_char;
use libc::c_int;
use libc::c_long;
use libc::c_uint;
use libc::c_void;
use libc::size_t;

use lazy_static;

use crate::Connection;
use crate::TransportParams;

use crate::crypto;
use crate::octets;
use crate::packet;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    TlsFail,
    WantRead,
    WantWrite,
    SyscallFail,
    PendingOperation,
}

const TLS1_3_VERSION: u16 = 0x0304;
const TLS_ALERT_ERROR: u16 = 0x100;

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
struct X509_VERIFY_PARAM(c_void);

#[repr(C)]
#[allow(non_camel_case_types)]
struct SSL_QUIC_METHOD {
    set_encryption_secrets: extern fn(
        ssl: *mut SSL,
        level: crypto::Level,
        read_secret: *const u8,
        write_secret: *const u8,
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
    static ref QUICHE_EX_DATA_INDEX: c_int = unsafe {
        SSL_get_ex_new_index(0, ptr::null(), ptr::null(), ptr::null(), ptr::null())
    };
}

static QUICHE_STREAM_METHOD: SSL_QUIC_METHOD = SSL_QUIC_METHOD {
    set_encryption_secrets,
    add_handshake_data,
    flush_flight,
    send_alert,
};

pub struct Context(*mut SSL_CTX);

impl Context {
    pub fn new() -> Result<Context> {
        unsafe {
            let ctx = SSL_CTX_new(TLS_method());

            map_result(SSL_CTX_set_default_verify_paths(ctx))?;

            Ok(Context(ctx))
        }
    }

    pub fn new_handshake(&mut self) -> Result<Handshake> {
        unsafe {
            let ssl = SSL_new(self.as_ptr());
            Ok(Handshake(ssl))
        }
    }

    pub fn use_certificate_chain_file(&mut self, file: &str) -> Result<()> {
        let cstr = ffi::CString::new(file).map_err(|_| Error::TlsFail)?;
        map_result(unsafe {
            SSL_CTX_use_certificate_chain_file(self.as_ptr(), cstr.as_ptr())
        })
    }

    pub fn use_privkey_file(&mut self, file: &str) -> Result<()> {
        let cstr = ffi::CString::new(file).map_err(|_| Error::TlsFail)?;
        map_result(unsafe {
            SSL_CTX_use_PrivateKey_file(self.as_ptr(), cstr.as_ptr(), 1)
        })
    }

    pub fn set_verify(&mut self, verify: bool) {
        let mode = if verify {
            0x01 // SSL_VERIFY_PEER
        } else {
            0x00 // SSL_VERIFY_NONE
        };

        unsafe {
            SSL_CTX_set_verify(self.as_ptr(), mode, ptr::null());
        }
    }

    pub fn enable_keylog(&mut self) {
        unsafe {
            SSL_CTX_set_keylog_callback(self.as_ptr(), keylog);
        }
    }

    pub fn set_alpn(&mut self, v: &[Vec<u8>]) -> Result<()> {
        let mut protos: Vec<u8> = Vec::new();

        for proto in v {
            protos.push(proto.len() as u8);
            protos.append(&mut proto.clone());
        }

        // Configure ALPN for servers.
        unsafe {
            SSL_CTX_set_alpn_select_cb(
                self.as_ptr(),
                select_alpn,
                ptr::null_mut(),
            );
        }

        // Configure ALPN for clients.
        map_result_zero_is_success(unsafe {
            SSL_CTX_set_alpn_protos(self.as_ptr(), protos.as_ptr(), protos.len())
        })
    }

    fn as_ptr(&self) -> *mut SSL_CTX {
        self.0
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        unsafe { SSL_CTX_free(self.as_ptr()) }
    }
}

pub struct Handshake(*mut SSL);

impl Handshake {
    pub fn from_void(ssl: *mut c_void) -> Handshake {
        let ssl = ssl as *mut SSL;
        Handshake(ssl)
    }

    pub fn get_error(&self, ret_code: c_int) -> c_int {
        unsafe { SSL_get_error(self.as_ptr(), ret_code) }
    }

    pub fn init(&self, conn: &Connection) -> Result<()> {
        self.set_state(conn.is_server);

        self.set_ex_data(*QUICHE_EX_DATA_INDEX, conn)?;

        self.set_min_proto_version(TLS1_3_VERSION);
        self.set_max_proto_version(TLS1_3_VERSION);

        self.set_quic_method()?;

        self.set_quiet_shutdown(true);

        let mut raw_params = [0; 128];

        let raw_params = TransportParams::encode(
            &conn.local_transport_params,
            conn.is_server,
            &mut raw_params,
        )
        .map_err(|_| Error::TlsFail)?;

        self.set_quic_transport_params(raw_params)?;

        Ok(())
    }

    pub fn set_state(&self, is_server: bool) {
        unsafe {
            if is_server {
                SSL_set_accept_state(self.as_ptr());
            } else {
                SSL_set_connect_state(self.as_ptr());
            }
        }
    }

    pub fn set_ex_data<T>(&self, idx: c_int, data: &T) -> Result<()> {
        map_result(unsafe {
            let ptr = data as *const T as *const c_void;
            SSL_set_ex_data(self.as_ptr(), idx, ptr)
        })
    }

    pub fn set_quic_method(&self) -> Result<()> {
        map_result(unsafe {
            SSL_set_quic_method(self.as_ptr(), &QUICHE_STREAM_METHOD)
        })
    }

    pub fn set_min_proto_version(&self, version: u16) {
        unsafe { SSL_set_min_proto_version(self.as_ptr(), version) }
    }

    pub fn set_max_proto_version(&self, version: u16) {
        unsafe { SSL_set_max_proto_version(self.as_ptr(), version) }
    }

    pub fn set_quiet_shutdown(&self, mode: bool) {
        unsafe { SSL_set_quiet_shutdown(self.as_ptr(), if mode { 1 } else { 0 }) }
    }

    pub fn set_host_name(&self, name: &str) -> Result<()> {
        let cstr = ffi::CString::new(name).map_err(|_| Error::TlsFail)?;
        map_result_ssl(self, unsafe {
            SSL_set_tlsext_host_name(self.as_ptr(), cstr.as_ptr())
        })?;

        let param = unsafe { SSL_get0_param(self.as_ptr()) };

        map_result(unsafe {
            X509_VERIFY_PARAM_set1_host(param, cstr.as_ptr(), name.len())
        })
    }

    pub fn set_quic_transport_params(&self, buf: &[u8]) -> Result<()> {
        map_result_ssl(self, unsafe {
            SSL_set_quic_transport_params(self.as_ptr(), buf.as_ptr(), buf.len())
        })
    }

    pub fn get_quic_transport_params(&self) -> &[u8] {
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

    pub fn get_alpn_protocol(&self) -> &[u8] {
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

    pub fn provide_data(&self, level: crypto::Level, buf: &[u8]) -> Result<()> {
        map_result_ssl(self, unsafe {
            SSL_provide_quic_data(self.as_ptr(), level, buf.as_ptr(), buf.len())
        })
    }

    pub fn do_handshake(&self) -> Result<()> {
        map_result_ssl(self, unsafe { SSL_do_handshake(self.as_ptr()) })
    }

    pub fn get_write_level(&self) -> crypto::Level {
        unsafe { SSL_quic_write_level(self.as_ptr()) }
    }

    pub fn cipher(&self) -> Result<crypto::Algorithm> {
        get_cipher_from_ptr(self.as_ptr())
    }

    pub fn is_resumed(&self) -> bool {
        unsafe { SSL_session_reused(self.as_ptr()) == 1 }
    }

    pub fn clear(&mut self) -> Result<()> {
        map_result_ssl(self, unsafe { SSL_clear(self.as_ptr()) })
    }

    fn as_ptr(&self) -> *mut SSL {
        self.0
    }
}

impl Drop for Handshake {
    fn drop(&mut self) {
        unsafe { SSL_free(self.as_ptr()) }
    }
}

fn get_ex_data_from_ptr<'a, T>(ptr: *mut SSL, idx: c_int) -> Option<&'a mut T> {
    unsafe {
        let data = SSL_get_ex_data(ptr, idx) as *mut T;
        data.as_mut()
    }
}

fn get_cipher_from_ptr(ptr: *mut SSL) -> Result<crypto::Algorithm> {
    let cipher = map_result_ptr(unsafe { SSL_get_current_cipher(ptr) })?;

    let cipher_id = unsafe { SSL_CIPHER_get_id(cipher) };

    let alg = match cipher_id {
        0x0300_1301 => crypto::Algorithm::AES128_GCM,
        0x0300_1302 => crypto::Algorithm::AES256_GCM,
        0x0300_1303 => crypto::Algorithm::ChaCha20_Poly1305,
        _ => return Err(Error::TlsFail),
    };

    Ok(alg)
}

extern fn set_encryption_secrets(
    ssl: *mut SSL, level: crypto::Level, read_secret: *const u8,
    write_secret: *const u8, secret_len: usize,
) -> c_int {
    let conn =
        match get_ex_data_from_ptr::<Connection>(ssl, *QUICHE_EX_DATA_INDEX) {
            Some(v) => v,
            None => return 0,
        };

    trace!(
        "{} tls set encryption secret lvl={:?}",
        conn.trace_id,
        level
    );

    let space = match level {
        crypto::Level::Initial => &mut conn.pkt_num_spaces[packet::EPOCH_INITIAL],
        // TODO: implement 0-RTT
        crypto::Level::ZeroRTT => unimplemented!("0-RTT"),
        crypto::Level::Handshake =>
            &mut conn.pkt_num_spaces[packet::EPOCH_HANDSHAKE],
        crypto::Level::Application =>
            &mut conn.pkt_num_spaces[packet::EPOCH_APPLICATION],
    };

    let aead = match get_cipher_from_ptr(ssl) {
        Ok(v) => v,
        Err(_) => return 0,
    };

    let key_len = aead.key_len();
    let nonce_len = aead.nonce_len();

    let mut key = vec![0; key_len];
    let mut iv = vec![0; nonce_len];
    let mut pn_key = vec![0; key_len];

    let secret = unsafe { slice::from_raw_parts(read_secret, secret_len) };

    if crypto::derive_pkt_key(aead, &secret, &mut key).is_err() {
        return 0;
    }

    if crypto::derive_pkt_iv(aead, &secret, &mut iv).is_err() {
        return 0;
    }

    if crypto::derive_hdr_key(aead, &secret, &mut pn_key).is_err() {
        return 0;
    }

    let open = match crypto::Open::new(aead, &key, &iv, &pn_key) {
        Ok(v) => v,
        Err(_) => return 0,
    };

    space.crypto_open = Some(open);

    let secret = unsafe { slice::from_raw_parts(write_secret, secret_len) };

    if crypto::derive_pkt_key(aead, &secret, &mut key).is_err() {
        return 0;
    }

    if crypto::derive_pkt_iv(aead, &secret, &mut iv).is_err() {
        return 0;
    }

    if crypto::derive_hdr_key(aead, &secret, &mut pn_key).is_err() {
        return 0;
    }

    let seal = match crypto::Seal::new(aead, &key, &iv, &pn_key) {
        Ok(v) => v,
        Err(_) => return 0,
    };

    space.crypto_seal = Some(seal);

    1
}

extern fn add_handshake_data(
    ssl: *mut SSL, level: crypto::Level, data: *const u8, len: usize,
) -> c_int {
    let conn =
        match get_ex_data_from_ptr::<Connection>(ssl, *QUICHE_EX_DATA_INDEX) {
            Some(v) => v,
            None => return 0,
        };

    trace!(
        "{} tls write message lvl={:?} len={}",
        conn.trace_id,
        level,
        len
    );

    let buf = unsafe { slice::from_raw_parts(data, len) };

    let space = match level {
        crypto::Level::Initial => &mut conn.pkt_num_spaces[packet::EPOCH_INITIAL],
        crypto::Level::ZeroRTT => unreachable!(),
        crypto::Level::Handshake =>
            &mut conn.pkt_num_spaces[packet::EPOCH_HANDSHAKE],
        crypto::Level::Application =>
            &mut conn.pkt_num_spaces[packet::EPOCH_APPLICATION],
    };

    if space.crypto_stream.send.push_slice(buf, false).is_err() {
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
    let conn =
        match get_ex_data_from_ptr::<Connection>(ssl, *QUICHE_EX_DATA_INDEX) {
            Some(v) => v,
            None => return 0,
        };

    trace!(
        "{} tls send alert lvl={:?} alert={:x}",
        conn.trace_id,
        level,
        alert
    );

    let error: u16 = TLS_ALERT_ERROR + u16::from(alert);
    conn.error = Some(error);

    1
}

extern fn keylog(_: *mut SSL, line: *const c_char) {
    if let Some(path) = std::env::var_os("SSLKEYLOGFILE") {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path);

        if let Ok(mut file) = file {
            let data = unsafe { ffi::CStr::from_ptr(line).to_bytes() };

            file.write_all(b"QUIC_").unwrap_or(());
            file.write_all(data).unwrap_or(());
            file.write_all(b"\n").unwrap_or(());
        }
    }
}

extern fn select_alpn(
    ssl: *mut SSL, out: *mut *const u8, out_len: *mut u8, inp: *mut u8,
    in_len: c_uint, _arg: *mut c_void,
) -> c_int {
    let conn =
        match get_ex_data_from_ptr::<Connection>(ssl, *QUICHE_EX_DATA_INDEX) {
            Some(v) => v,
            None => return 3, // SSL_TLSEXT_ERR_NOACK
        };

    if conn.application_protos.is_empty() {
        return 3; // SSL_TLSEXT_ERR_NOACK
    }

    let mut protos = octets::Octets::with_slice(unsafe {
        slice::from_raw_parts_mut(inp, in_len as usize)
    });

    while let Ok(proto) = protos.get_bytes_with_u8_length() {
        let found = conn.application_protos.iter().any(|expected| {
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

fn map_result_ssl(ssl: &Handshake, bssl_result: c_int) -> Result<()> {
    match bssl_result {
        1 => Ok(()),

        _ => {
            let ssl_err = ssl.get_error(bssl_result);
            match ssl_err {
                // SSL_ERROR_SSL
                1 => {
                    log_ssl_error();

                    Err(Error::TlsFail)
                },

                // SSL_ERROR_WANT_READ
                2 => Err(Error::WantRead),

                // SSL_ERROR_WANT_WRITE
                3 => Err(Error::WantWrite),

                // SSL_ERROR_WANT_X509_LOOKUP
                4 => Err(Error::PendingOperation),

                // SSL_ERROR_SYSCALL
                5 => Err(Error::SyscallFail),

                // SSL_ERROR_PENDING_CERTIFICATE
                12 => Err(Error::PendingOperation),

                // SSL_ERROR_WANT_PRIVATE_KEY_OPERATION
                13 => Err(Error::PendingOperation),

                // SSL_ERROR_PENDING_TICKET
                14 => Err(Error::PendingOperation),

                _ => Err(Error::TlsFail),
            }
        },
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

    fn SSL_CTX_set_default_verify_paths(ctx: *mut SSL_CTX) -> c_int;

    fn SSL_CTX_set_verify(ctx: *mut SSL_CTX, mode: c_int, cb: *const c_void);

    fn SSL_CTX_set_keylog_callback(
        ctx: *mut SSL_CTX, cb: extern fn(ssl: *mut SSL, line: *const c_char),
    );

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

    // SSL
    fn SSL_get_ex_new_index(
        argl: c_long, argp: *const c_void, unused: *const c_void,
        dup_unused: *const c_void, free_func: *const c_void,
    ) -> c_int;

    fn SSL_new(ctx: *mut SSL_CTX) -> *mut SSL;

    fn SSL_get_error(ssl: *mut SSL, ret_code: c_int) -> c_int;

    fn SSL_set_accept_state(ssl: *mut SSL);
    fn SSL_set_connect_state(ssl: *mut SSL);

    fn SSL_get0_param(ssl: *mut SSL) -> *mut X509_VERIFY_PARAM;

    fn SSL_set_ex_data(ssl: *mut SSL, idx: c_int, ptr: *const c_void) -> c_int;
    fn SSL_get_ex_data(ssl: *mut SSL, idx: c_int) -> *mut c_void;

    fn SSL_get_current_cipher(ssl: *mut SSL) -> *const SSL_CIPHER;

    fn SSL_set_min_proto_version(ssl: *mut SSL, version: u16);
    fn SSL_set_max_proto_version(ssl: *mut SSL, version: u16);

    fn SSL_set_quiet_shutdown(ssl: *mut SSL, mode: c_int);

    fn SSL_set_tlsext_host_name(ssl: *mut SSL, name: *const c_char) -> c_int;

    fn SSL_set_quic_transport_params(
        ssl: *mut SSL, params: *const u8, params_len: usize,
    ) -> c_int;

    fn SSL_set_quic_method(
        ssl: *mut SSL, quic_method: *const SSL_QUIC_METHOD,
    ) -> c_int;

    fn SSL_get_peer_quic_transport_params(
        ssl: *mut SSL, out_params: *mut *const u8, out_params_len: *mut usize,
    );

    fn SSL_get0_alpn_selected(
        ssl: *mut SSL, out: *mut *const u8, out_len: *mut u32,
    );

    fn SSL_provide_quic_data(
        ssl: *mut SSL, level: crypto::Level, data: *const u8, len: usize,
    ) -> c_int;

    fn SSL_do_handshake(ssl: *mut SSL) -> c_int;

    fn SSL_quic_write_level(ssl: *mut SSL) -> crypto::Level;

    fn SSL_session_reused(ssl: *mut SSL) -> c_int;

    fn SSL_clear(ssl: *mut SSL) -> c_int;

    fn SSL_free(ssl: *mut SSL);

    // SSL_CIPHER
    fn SSL_CIPHER_get_id(cipher: *const SSL_CIPHER) -> c_uint;

    // X509_VERIFY_PARAM
    fn X509_VERIFY_PARAM_set1_host(
        param: *mut X509_VERIFY_PARAM, name: *const c_char, namelen: size_t,
    ) -> c_int;

    // ERR
    fn ERR_peek_error() -> c_uint;

    fn ERR_error_string_n(err: c_uint, buf: *const u8, len: usize);
}
