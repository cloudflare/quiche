// Copyright (c) 2018, Alessandro Ghedini
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
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

use libc::c_void;

use ::Connection;

use crypto;

pub type Result<T> = ::std::result::Result<T, Error>;

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

#[repr(C)]
#[allow(non_camel_case_types)]
struct SSL_QUIC_METHOD {
    set_encryption_secrets:
        extern fn(ssl: *mut SSL, level: crypto::Level, read_secret: *const u8,
                  write_secret: *const u8, secret_len: usize) -> i32,

    add_handshake_data:
        extern fn(ssl: *mut SSL, level: crypto::Level, data: *const u8,
                  len: usize) -> i32,

    flush_flight: extern fn(ssl: *mut SSL) -> i32,

    send_alert: extern fn(ssl: *mut SSL, level: crypto::Level, alert: u8) -> i32,
}

lazy_static! {
    static ref QUICHE_EX_DATA_INDEX: i32 = unsafe {
        SSL_get_ex_new_index(0, ptr::null(), ptr::null(), ptr::null(), ptr::null())
    };
}

static QUICHE_STREAM_METHOD: SSL_QUIC_METHOD = SSL_QUIC_METHOD {
    set_encryption_secrets,
    add_handshake_data,
    flush_flight,
    send_alert,
};

const SSL_OP_NO_TICKET: u32 = 0x00004000;
const SSL_OP_CIPHER_SERVER_PREFERENCE: u32 = 0x00400000;
const SSL_OP_NO_TLSV1: u32 = 0x04000000;
const SSL_OP_NO_TLSV1_1: u32 = 0x10000000;
const SSL_OP_NO_TLSV1_2: u32 = 0x08000000;

pub struct State(*mut SSL);

impl State {
    pub fn new() -> Result<State> {
        unsafe {
            // TODO: expose SSL_CTX to applications so we don't need to parse
            // certificates for each connection.
            let ctx = SSL_CTX_new(TLS_method());
            // TODO: enable session tickets (debug problem with quant)
            SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET |
                                     SSL_OP_CIPHER_SERVER_PREFERENCE |
                                     SSL_OP_NO_TLSV1 |
                                     SSL_OP_NO_TLSV1_1 |
                                     SSL_OP_NO_TLSV1_2);

            map_result(SSL_CTX_set_quic_method(ctx, &QUICHE_STREAM_METHOD))?;

            let ssl = SSL_new(ctx);
            SSL_CTX_free(ctx);

            Ok(State(ssl))
        }
    }

    pub fn get_error(&self, ret_code: i32) -> i32 {
        unsafe {
            SSL_get_error(self.as_ptr(), ret_code)
        }
    }

    pub fn init_with_conn(&self, conn: &::Connection) -> Result<()> {
        self.set_state(conn.is_server);

        self.set_ex_data(*QUICHE_EX_DATA_INDEX, conn)?;

        self.set_min_proto_version(TLS1_3_VERSION);
        self.set_max_proto_version(TLS1_3_VERSION);

        self.set_quiet_shutdown(true);

        let mut raw_params: [u8; 128] = [0; 128];

        let raw_params = ::TransportParams::encode(&conn.local_transport_params,
                                                   conn.version, conn.is_server,
                                                   &mut raw_params)
                                           .map_err(|_e| Error::TlsFail)?;

        self.set_quic_transport_params(raw_params)?;

        Ok(())
    }

    pub fn init_with_conn_extra(&self, conn: &::Connection, config: &::Config)
                                                            -> Result<()> {
        self.init_with_conn(conn)?;

        if config.tls_server_name.len() > 0 {
            self.set_server_name(config.tls_server_name)?;
        }

        if config.tls_certificate.len() > 0 {
            self.use_certificate_file(config.tls_certificate)?;
        }

        if config.tls_certificate_key.len() > 0 {
            self.use_privkey_file(config.tls_certificate_key)?;
        }

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

    pub fn set_ex_data<T>(&self, idx: i32, data: &T) -> Result<()> {
        map_result(unsafe {
            let ptr = data as *const T as *const c_void;
            SSL_set_ex_data(self.as_ptr(), idx, ptr)
        })
    }

    pub fn set_min_proto_version(&self, version: u16) {
        unsafe {
            SSL_set_min_proto_version(self.as_ptr(), version)
        }
    }

    pub fn set_max_proto_version(&self, version: u16) {
        unsafe {
            SSL_set_max_proto_version(self.as_ptr(), version)
        }
    }

    pub fn set_quiet_shutdown(&self, mode: bool) {
        unsafe {
            SSL_set_quiet_shutdown(self.as_ptr(), if mode { 1 } else { 0 })
        }
    }

    pub fn set_server_name(&self, name: &str) -> Result<()> {
        let cstr = ffi::CString::new(name).map_err(|_e| Error::TlsFail)?;
        map_result_ssl(self, unsafe {
            SSL_set_tlsext_host_name(self.as_ptr(), cstr.as_ptr())
        })
    }

    pub fn set_quic_transport_params(&self, buf: &[u8]) -> Result<()> {
        map_result_ssl(self, unsafe {
            SSL_set_quic_transport_params(self.as_ptr(), buf.as_ptr(), buf.len())
        })
    }

    pub fn get_quic_transport_params(&self) -> Result<&mut [u8]> {
        let mut ptr: *mut u8 = ptr::null_mut();
        let mut len: usize = 0;

        unsafe {
            SSL_get_peer_quic_transport_params(self.as_ptr(),
                                               &mut ptr as *mut *mut u8,
                                               &mut len)
        };

        Ok(unsafe { slice::from_raw_parts_mut(ptr, len) })
    }

    pub fn provide_data(&self, level: crypto::Level, buf: &[u8]) -> Result<()> {
        map_result_ssl(self, unsafe {
            SSL_provide_quic_data(self.as_ptr(), level, buf.as_ptr(), buf.len())
        })
    }

    pub fn do_handshake(&self) -> Result<()> {
        map_result_ssl(self, unsafe {
            SSL_do_handshake(self.as_ptr())
        })
    }

    pub fn use_certificate_file(&self, file: &str) -> Result<()> {
        let cstr = ffi::CString::new(file).map_err(|_e| Error::TlsFail)?;
        // TODO: support parsing and configuring full chain
        map_result_ssl(self, unsafe {
            SSL_use_certificate_file(self.as_ptr(), cstr.as_ptr(), 1)
        })
    }

    pub fn use_privkey_file(&self, file: &str) -> Result<()> {
        let cstr = ffi::CString::new(file).map_err(|_e| Error::TlsFail)?;
        map_result_ssl(self, unsafe {
            SSL_use_PrivateKey_file(self.as_ptr(), cstr.as_ptr(), 1)
        })
    }

    pub fn get_write_level(&mut self) -> crypto::Level {
        unsafe {
            SSL_quic_write_level(self.as_ptr())
        }
    }

    pub fn clear(&mut self) -> Result<()> {
        map_result_ssl(self, unsafe {
            SSL_clear(self.as_ptr())
        })
    }

    fn as_ptr(&self) -> *mut SSL {
        self.0
    }
}

impl Drop for State {
    fn drop(&mut self) {
        unsafe { SSL_free(self.as_ptr()) }
    }
}

fn get_ex_data_from_ptr<'a, T>(ptr: *mut SSL, idx: i32) -> Option<&'a mut T> {
    unsafe {
        let data = SSL_get_ex_data(ptr, idx) as *mut T;
        data.as_mut()
    }
}

fn get_pending_cipher_from_ptr(ptr: *mut SSL) -> Result<crypto::Algorithm> {
    let cipher = map_result_ptr(unsafe {
        SSL_get_pending_cipher(ptr)
    })?;

    let cipher_id = unsafe {
        SSL_CIPHER_get_id(cipher as *const SSL_CIPHER)
    };

    let alg = match cipher_id {
        0x0300_1301 => crypto::Algorithm::AES128_GCM,
        0x0300_1302 => crypto::Algorithm::AES256_GCM,
        0x0300_1303 => crypto::Algorithm::ChaCha20_Poly1305,
        _           => return Err(Error::TlsFail),
    };

    Ok(alg)
}

extern fn set_encryption_secrets(ssl: *mut SSL, level: crypto::Level,
                                 read_secret: *const u8,
                                 write_secret: *const u8,
                                 secret_len: usize) -> i32 {
    let conn = match get_ex_data_from_ptr::<Connection>(ssl, *QUICHE_EX_DATA_INDEX) {
        Some(v) => v,
        None    => return 0,
    };

    trace!("{} tls set encryption secret lvl={:?}", conn.trace_id(), level);

    let space = match level {
        crypto::Level::Initial     => &mut conn.initial,
        // TODO: implement 0-RTT
        crypto::Level::ZeroRTT     => panic!("0-RTT not implemented"),
        crypto::Level::Handshake   => &mut conn.handshake,
        crypto::Level::Application => &mut conn.application,
    };

    let aead = match get_pending_cipher_from_ptr(ssl) {
        Ok(v)  => v,
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

    if crypto::derive_pkt_num_key(aead, &secret, &mut pn_key).is_err() {
        return 0;
    }

    let open = match crypto::Open::new(aead, &key, &iv, &pn_key) {
        Ok(v)  => v,
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

    if crypto::derive_pkt_num_key(aead, &secret, &mut pn_key).is_err() {
        return 0;
    }

    let seal = match crypto::Seal::new(aead, &key, &iv, &pn_key) {
        Ok(v)  => v,
        Err(_) => return 0,
    };

    space.crypto_seal = Some(seal);

    1
}

extern fn add_handshake_data(ssl: *mut SSL, level: crypto::Level,
                             data: *const u8, len: usize) -> i32 {
    let conn = match get_ex_data_from_ptr::<Connection>(ssl, *QUICHE_EX_DATA_INDEX) {
        Some(v) => v,
        None    => return 0,
    };

    trace!("{} tls write message lvl={:?} len={}", conn.trace_id(), level, len);

    let buf = unsafe { slice::from_raw_parts(data, len) };

    let space = match level {
        crypto::Level::Initial     => &mut conn.initial,
        // TODO: implement 0-RTT
        crypto::Level::ZeroRTT     => panic!("0-RTT not implemented"),
        crypto::Level::Handshake   => &mut conn.handshake,
        crypto::Level::Application => &mut conn.application,
    };

    if space.crypto_stream.push_send(buf, false).is_err() {
        return 0;
    }

    1
}

extern fn flush_flight(_ssl: *mut SSL) -> i32 {
    // We don't really need to anything here since the output packets are
    // generated separately, when conn.send() is called.

    1
}

extern fn send_alert(ssl: *mut SSL, level: crypto::Level, alert: u8) -> i32 {
    let conn = match get_ex_data_from_ptr::<Connection>(ssl, *QUICHE_EX_DATA_INDEX) {
        Some(v) => v,
        None    => return 0,
    };

    trace!("{} tls send alert lvl={:?} alert={:x}",
           conn.trace_id(), level, alert);

    let error: u16 = TLS_ALERT_ERROR + u16::from(alert);
    conn.error = Some(error);

    1
}

fn map_result(bssl_result: i32) -> Result<()> {
    match bssl_result {
        1 => Ok(()),
        _ => Err(Error::TlsFail),
    }
}

fn map_result_ptr<'a, T>(bssl_result: *const T) -> Result<&'a T> {
    match unsafe { bssl_result.as_ref() } {
        Some(v) => Ok(v),
        None    => Err(Error::TlsFail),
    }
}

fn map_result_ssl(ssl: &State, bssl_result: i32) -> Result<()> {
    match bssl_result {
        1 => Ok(()),
        _ => {
            let ssl_err = ssl.get_error(bssl_result);
            match ssl_err {
                // SSL_ERROR_SSL
                1 => Err(Error::TlsFail),

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
        }
    }
}

extern {
    // SSL_METHOD
    fn TLS_method() -> *const SSL_METHOD;

    // SSL_CTX
    fn SSL_CTX_new(method: *const SSL_METHOD) -> *mut SSL_CTX;
    fn SSL_CTX_free(ctx: *mut SSL_CTX);

    fn SSL_CTX_set_options(ctx: *mut SSL_CTX, options: u32) -> u32;

    fn SSL_CTX_set_quic_method(ctx: *mut SSL_CTX,
        quic_method: *const SSL_QUIC_METHOD) -> i32;

    // SSL
    fn SSL_get_ex_new_index(argl: libc::c_long, argp: *const c_void,
        unused: *const c_void, dup_unused: *const c_void,
        free_func: *const c_void) -> i32;

    fn SSL_new(ctx: *mut SSL_CTX) -> *mut SSL;

    fn SSL_get_error(ssl: *mut SSL, ret_code: i32) -> i32;

    fn SSL_set_accept_state(ssl: *mut SSL);
    fn SSL_set_connect_state(ssl: *mut SSL);

    fn SSL_set_ex_data(ssl: *mut SSL, idx: i32, ptr: *const c_void) -> i32;
    fn SSL_get_ex_data(ssl: *mut SSL, idx: i32) -> *mut c_void;

    fn SSL_get_pending_cipher(ssl: *mut SSL) -> *const SSL_CIPHER;

    fn SSL_set_min_proto_version(ssl: *mut SSL, version: u16);
    fn SSL_set_max_proto_version(ssl: *mut SSL, version: u16);

    fn SSL_set_quiet_shutdown(ssl: *mut SSL, mode: i32);

    fn SSL_set_tlsext_host_name(ssl: *mut SSL, name: *const libc::c_char) -> i32;

    fn SSL_set_quic_transport_params(ssl: *mut SSL, params: *const u8,
        params_len: usize) -> i32;

    fn SSL_get_peer_quic_transport_params(ssl: *mut SSL,
        out_params: *mut *mut u8, out_params_len: *mut usize);

    fn SSL_provide_quic_data(ssl: *mut SSL, level: crypto::Level,
        data: *const u8, len: usize) -> i32;

    fn SSL_do_handshake(ssl: *mut SSL) -> i32;

    fn SSL_use_certificate_file(ssl: *mut SSL, file: *const libc::c_char,
                                ty: libc::c_int) -> libc::c_int;

    fn SSL_use_PrivateKey_file(ssl: *mut SSL, file: *const libc::c_char,
                               ty: libc::c_int) -> libc::c_int;

    fn SSL_quic_write_level(ssl: *mut SSL) -> crypto::Level;

    fn SSL_clear(ssl: *mut SSL) -> i32;

    fn SSL_free(ssl: *mut SSL);

    // SSL_CIPHER
    fn SSL_CIPHER_get_id(cipher: *const SSL_CIPHER) -> u32;
}
