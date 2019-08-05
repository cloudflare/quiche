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
use std::sync::atomic;

use libc::c_char;
use libc::c_int;
use libc::c_void;
use libc::size_t;
use libc::ssize_t;

use crate::*;

#[no_mangle]
pub extern fn quiche_version() -> *const u8 {
    static VERSION: &'static str = concat!(env!("CARGO_PKG_VERSION"), "\0");
    VERSION.as_ptr()
}

struct Logger {
    cb: extern fn(line: *const u8, argp: *mut c_void),
    argp: std::sync::atomic::AtomicPtr<c_void>,
}

impl log::Log for Logger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        let line = format!("{}: {}\0", record.target(), record.args());
        (self.cb)(line.as_ptr(), self.argp.load(atomic::Ordering::Relaxed));
    }

    fn flush(&self) {}
}

#[no_mangle]
pub extern fn quiche_enable_debug_logging(
    cb: extern fn(line: *const u8, argp: *mut c_void), argp: *mut c_void,
) {
    let argp = atomic::AtomicPtr::new(argp);
    let logger = Box::new(Logger { cb, argp });

    log::set_boxed_logger(logger).unwrap();
    log::set_max_level(log::LevelFilter::Trace);
}

#[no_mangle]
pub extern fn quiche_config_new(version: u32) -> *mut Config {
    match Config::new(version) {
        Ok(c) => Box::into_raw(Box::new(c)),

        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub extern fn quiche_config_load_cert_chain_from_pem_file(
    config: &mut Config, path: *const c_char,
) -> c_int {
    let path = unsafe { ffi::CStr::from_ptr(path).to_str().unwrap() };

    match config.load_cert_chain_from_pem_file(path) {
        Ok(_) => 0,

        Err(e) => e.to_c() as c_int,
    }
}

#[no_mangle]
pub extern fn quiche_config_load_priv_key_from_pem_file(
    config: &mut Config, path: *const c_char,
) -> c_int {
    let path = unsafe { ffi::CStr::from_ptr(path).to_str().unwrap() };

    match config.load_priv_key_from_pem_file(path) {
        Ok(_) => 0,

        Err(e) => e.to_c() as c_int,
    }
}

#[no_mangle]
pub extern fn quiche_config_verify_peer(config: &mut Config, v: bool) {
    config.verify_peer(v);
}

#[no_mangle]
pub extern fn quiche_config_grease(config: &mut Config, v: bool) {
    config.grease(v);
}

#[no_mangle]
pub extern fn quiche_config_log_keys(config: &mut Config) {
    config.log_keys();
}

#[no_mangle]
pub extern fn quiche_config_set_application_protos(
    config: &mut Config, protos: *const u8, protos_len: size_t,
) -> c_int {
    let protos = unsafe { slice::from_raw_parts(protos, protos_len) };

    match config.set_application_protos(protos) {
        Ok(_) => 0,

        Err(e) => e.to_c() as c_int,
    }
}

#[no_mangle]
pub extern fn quiche_config_set_idle_timeout(config: &mut Config, v: u64) {
    config.set_idle_timeout(v);
}

#[no_mangle]
pub extern fn quiche_config_set_max_packet_size(config: &mut Config, v: u64) {
    config.set_max_packet_size(v);
}

#[no_mangle]
pub extern fn quiche_config_set_initial_max_data(config: &mut Config, v: u64) {
    config.set_initial_max_data(v);
}

#[no_mangle]
pub extern fn quiche_config_set_initial_max_stream_data_bidi_local(
    config: &mut Config, v: u64,
) {
    config.set_initial_max_stream_data_bidi_local(v);
}

#[no_mangle]
pub extern fn quiche_config_set_initial_max_stream_data_bidi_remote(
    config: &mut Config, v: u64,
) {
    config.set_initial_max_stream_data_bidi_remote(v);
}

#[no_mangle]
pub extern fn quiche_config_set_initial_max_stream_data_uni(
    config: &mut Config, v: u64,
) {
    config.set_initial_max_stream_data_uni(v);
}

#[no_mangle]
pub extern fn quiche_config_set_initial_max_streams_bidi(
    config: &mut Config, v: u64,
) {
    config.set_initial_max_streams_bidi(v);
}

#[no_mangle]
pub extern fn quiche_config_set_initial_max_streams_uni(
    config: &mut Config, v: u64,
) {
    config.set_initial_max_streams_uni(v);
}

#[no_mangle]
pub extern fn quiche_config_set_ack_delay_exponent(config: &mut Config, v: u64) {
    config.set_ack_delay_exponent(v);
}

#[no_mangle]
pub extern fn quiche_config_set_max_ack_delay(config: &mut Config, v: u64) {
    config.set_max_ack_delay(v);
}

#[no_mangle]
pub extern fn quiche_config_set_disable_migration(config: &mut Config, v: bool) {
    config.set_disable_migration(v);
}

#[no_mangle]
pub extern fn quiche_config_free(config: *mut Config) {
    unsafe { Box::from_raw(config) };
}

#[no_mangle]
pub extern fn quiche_header_info(
    buf: *mut u8, buf_len: size_t, dcil: size_t, version: *mut u32, ty: *mut u8,
    scid: *mut u8, scid_len: *mut size_t, dcid: *mut u8, dcid_len: *mut size_t,
    token: *mut u8, token_len: *mut size_t,
) -> c_int {
    let buf = unsafe { slice::from_raw_parts_mut(buf, buf_len) };
    let hdr = match Header::from_slice(buf, dcil) {
        Ok(h) => h,

        Err(e) => return e.to_c() as c_int,
    };

    unsafe {
        *version = hdr.version;

        *ty = match hdr.ty {
            Type::Initial => 1,
            Type::Retry => 2,
            Type::Handshake => 3,
            Type::ZeroRTT => 4,
            Type::Application => 5,
            Type::VersionNegotiation => 6,
        };

        if *scid_len < hdr.scid.len() {
            return -1;
        }

        let scid = slice::from_raw_parts_mut(scid, *scid_len);
        let scid = &mut scid[..hdr.scid.len()];
        scid.copy_from_slice(&hdr.scid);

        *scid_len = hdr.scid.len();

        if *dcid_len < hdr.dcid.len() {
            return -1;
        }

        let dcid = slice::from_raw_parts_mut(dcid, *dcid_len);
        let dcid = &mut dcid[..hdr.dcid.len()];
        dcid.copy_from_slice(&hdr.dcid);

        *dcid_len = hdr.dcid.len();

        match hdr.token {
            Some(tok) => {
                if *token_len < tok.len() {
                    return -1;
                }

                let token = slice::from_raw_parts_mut(token, *token_len);
                let token = &mut token[..tok.len()];
                token.copy_from_slice(&tok);

                *token_len = tok.len();
            },

            None => *token_len = 0,
        }
    }

    0
}

#[no_mangle]
pub extern fn quiche_accept(
    scid: *const u8, scid_len: size_t, odcid: *const u8, odcid_len: size_t,
    config: &mut Config,
) -> *mut Connection {
    let scid = unsafe { slice::from_raw_parts(scid, scid_len) };

    let odcid = if !odcid.is_null() || odcid_len == 0 {
        Some(unsafe { slice::from_raw_parts(odcid, odcid_len) })
    } else {
        None
    };

    match accept(scid, odcid, config) {
        Ok(c) => Box::into_raw(c),

        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub extern fn quiche_connect(
    server_name: *const c_char, scid: *const u8, scid_len: size_t,
    config: &mut Config,
) -> *mut Connection {
    let server_name = if server_name.is_null() {
        None
    } else {
        Some(unsafe { ffi::CStr::from_ptr(server_name).to_str().unwrap() })
    };

    let scid = unsafe { slice::from_raw_parts(scid, scid_len) };

    match connect(server_name, scid, config) {
        Ok(c) => Box::into_raw(c),

        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub extern fn quiche_negotiate_version(
    scid: *const u8, scid_len: size_t, dcid: *const u8, dcid_len: size_t,
    out: *mut u8, out_len: size_t,
) -> ssize_t {
    let scid = unsafe { slice::from_raw_parts(scid, scid_len) };
    let dcid = unsafe { slice::from_raw_parts(dcid, dcid_len) };
    let out = unsafe { slice::from_raw_parts_mut(out, out_len) };

    match negotiate_version(scid, dcid, out) {
        Ok(v) => v as ssize_t,

        Err(e) => e.to_c(),
    }
}

#[no_mangle]
pub extern fn quiche_retry(
    scid: *const u8, scid_len: size_t, dcid: *const u8, dcid_len: size_t,
    new_scid: *const u8, new_scid_len: size_t, token: *const u8,
    token_len: size_t, out: *mut u8, out_len: size_t,
) -> ssize_t {
    let scid = unsafe { slice::from_raw_parts(scid, scid_len) };
    let dcid = unsafe { slice::from_raw_parts(dcid, dcid_len) };
    let new_scid = unsafe { slice::from_raw_parts(new_scid, new_scid_len) };
    let token = unsafe { slice::from_raw_parts(token, token_len) };
    let out = unsafe { slice::from_raw_parts_mut(out, out_len) };

    match retry(scid, dcid, new_scid, token, out) {
        Ok(v) => v as ssize_t,

        Err(e) => e.to_c(),
    }
}

#[no_mangle]
pub extern fn quiche_conn_new_with_tls(
    scid: *const u8, scid_len: size_t, odcid: *const u8, odcid_len: size_t,
    config: &mut Config, ssl: *mut c_void, is_server: bool,
) -> *mut Connection {
    let scid = unsafe { slice::from_raw_parts(scid, scid_len) };

    let odcid = if !odcid.is_null() || odcid_len == 0 {
        Some(unsafe { slice::from_raw_parts(odcid, odcid_len) })
    } else {
        None
    };

    let tls = unsafe { tls::Handshake::from_ptr(ssl) };

    match Connection::with_tls(scid, odcid, config, tls, is_server) {
        Ok(c) => Box::into_raw(c),

        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub extern fn quiche_conn_recv(
    conn: &mut Connection, buf: *mut u8, buf_len: size_t,
) -> ssize_t {
    if buf_len > <ssize_t>::max_value() as usize {
        panic!("The provided buffer is too large");
    }

    let buf = unsafe { slice::from_raw_parts_mut(buf, buf_len) };

    match conn.recv(buf) {
        Ok(v) => v as ssize_t,

        Err(e) => e.to_c(),
    }
}

#[no_mangle]
pub extern fn quiche_conn_send(
    conn: &mut Connection, out: *mut u8, out_len: size_t,
) -> ssize_t {
    if out_len > <ssize_t>::max_value() as usize {
        panic!("The provided buffer is too large");
    }

    let out = unsafe { slice::from_raw_parts_mut(out, out_len) };

    match conn.send(out) {
        Ok(v) => v as ssize_t,

        Err(e) => e.to_c(),
    }
}

#[no_mangle]
pub extern fn quiche_conn_stream_recv(
    conn: &mut Connection, stream_id: u64, out: *mut u8, out_len: size_t,
    fin: &mut bool,
) -> ssize_t {
    if out_len > <ssize_t>::max_value() as usize {
        panic!("The provided buffer is too large");
    }

    let out = unsafe { slice::from_raw_parts_mut(out, out_len) };

    let (out_len, out_fin) = match conn.stream_recv(stream_id, out) {
        Ok(v) => v,

        Err(e) => return e.to_c(),
    };

    *fin = out_fin;

    out_len as ssize_t
}

#[no_mangle]
pub extern fn quiche_conn_stream_send(
    conn: &mut Connection, stream_id: u64, buf: *const u8, buf_len: size_t,
    fin: bool,
) -> ssize_t {
    if buf_len > <ssize_t>::max_value() as usize {
        panic!("The provided buffer is too large");
    }

    let buf = unsafe { slice::from_raw_parts(buf, buf_len) };

    match conn.stream_send(stream_id, buf, fin) {
        Ok(v) => v as ssize_t,

        Err(e) => e.to_c(),
    }
}

#[no_mangle]
pub extern fn quiche_conn_stream_shutdown(
    conn: &mut Connection, stream_id: u64, direction: Shutdown, err: u64,
) -> c_int {
    match conn.stream_shutdown(stream_id, direction, err) {
        Ok(_) => 0,

        Err(e) => e.to_c() as c_int,
    }
}

#[no_mangle]
pub extern fn quiche_conn_stream_finished(
    conn: &mut Connection, stream_id: u64,
) -> bool {
    conn.stream_finished(stream_id)
}

#[no_mangle]
pub extern fn quiche_readable_next(
    conn: &mut Connection, stream_id: *mut u64,
) -> bool {
    if let Some(v) = conn.readable().next() {
        unsafe { *stream_id = v };
        return true;
    }

    false
}

#[no_mangle]
pub extern fn quiche_conn_close(
    conn: &mut Connection, app: bool, err: u64, reason: *const u8,
    reason_len: size_t,
) -> c_int {
    let reason = unsafe { slice::from_raw_parts(reason, reason_len) };

    match conn.close(app, err, reason) {
        Ok(_) => 0,

        Err(e) => e.to_c() as c_int,
    }
}

#[no_mangle]
pub extern fn quiche_conn_timeout_as_nanos(conn: &mut Connection) -> u64 {
    match conn.timeout() {
        Some(timeout) => timeout.as_nanos() as u64,

        None => std::u64::MAX,
    }
}

#[no_mangle]
pub extern fn quiche_conn_on_timeout(conn: &mut Connection) {
    conn.on_timeout()
}

#[no_mangle]
pub extern fn quiche_conn_application_proto(
    conn: &mut Connection, out: &mut *const u8, out_len: &mut size_t,
) {
    let proto = conn.application_proto();

    *out = proto.as_ptr();
    *out_len = proto.len();
}

#[no_mangle]
pub extern fn quiche_conn_is_established(conn: &mut Connection) -> bool {
    conn.is_established()
}

#[no_mangle]
pub extern fn quiche_conn_is_closed(conn: &mut Connection) -> bool {
    conn.is_closed()
}

#[repr(C)]
pub struct Stats {
    pub recv: usize,
    pub sent: usize,
    pub lost: usize,
    pub rtt: u64,
    pub cwnd: usize,
}

#[no_mangle]
pub extern fn quiche_conn_stats(conn: &Connection, out: &mut Stats) {
    let stats = conn.stats();

    out.recv = stats.recv;
    out.sent = stats.sent;
    out.lost = stats.lost;
    out.rtt = stats.rtt.as_nanos() as u64;
    out.cwnd = stats.cwnd;
}

#[no_mangle]
pub extern fn quiche_conn_free(conn: *mut Connection) {
    unsafe { Box::from_raw(conn) };
}
