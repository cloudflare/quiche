// Copyright (C) 2018, Cloudflare, Inc.
// Copyright (C) 2018, Alessandro Ghedini
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
use std::sync::atomic;

use libc::c_char;
use libc::c_int;
use libc::c_void;
use libc::ssize_t;

use crate::*;

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
pub extern fn quiche_enable_debug_logging(cb: extern fn(line: *const u8,
                                                        argp: *mut c_void),
                                          argp: *mut c_void) {
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
pub extern fn quiche_config_load_cert_chain_from_pem_file(config: &mut Config,
                                                          path: *const c_char)
                                                            -> c_int {
    let path = unsafe { ffi::CStr::from_ptr(path).to_str().unwrap() };

    match config.load_cert_chain_from_pem_file(path) {
        Ok(_) => 0,

        Err(e) => e.to_c() as c_int,
    }
}

#[no_mangle]
pub extern fn quiche_config_load_priv_key_from_pem_file(config: &mut Config,
                                                        path: *const c_char)
                                                            -> c_int {
    let path = unsafe { ffi::CStr::from_ptr(path).to_str().unwrap() };

    match config.load_priv_key_from_pem_file(path) {
        Ok(_) => 0,

        Err(e) => e.to_c() as c_int,
    }
}

#[no_mangle]
pub extern fn quiche_config_log_keys(config: &mut Config) {
    config.log_keys();
}

#[no_mangle]
pub extern fn quiche_config_set_idle_timeout(config: &mut Config, v: u64) {
    config.set_idle_timeout(v);
}

#[no_mangle]
pub extern fn quiche_config_set_initial_max_stream_data_bidi_local(config: &mut Config, v: u64) {
    config.set_initial_max_stream_data_bidi_local(v);
}

#[no_mangle]
pub extern fn quiche_config_set_initial_max_stream_data_bidi_remote(config: &mut Config, v: u64) {
    config.set_initial_max_stream_data_bidi_remote(v);
}

#[no_mangle]
pub extern fn quiche_config_set_initial_max_data(config: &mut Config, v: u64) {
    config.set_initial_max_data(v);
}

#[no_mangle]
pub extern fn quiche_config_set_initial_max_streams_bidi(config: &mut Config, v: u64) {
    config.set_initial_max_streams_bidi(v);
}

#[no_mangle]
pub extern fn quiche_config_free(config: *mut Config) {
    unsafe { Box::from_raw(config) };
}

#[no_mangle]
pub extern fn quiche_header_info(buf: *mut u8, buf_len: usize, dcil: usize,
                                 version: *mut u32, ty: *mut u8,
                                 dcid: *mut u8, dcid_len: *mut usize) -> c_int {
    let buf = unsafe { slice::from_raw_parts_mut(buf, buf_len) };
    let hdr = match Header::from_slice(buf, dcil) {
        Ok(h) => h,

        Err(e) => return e.to_c() as c_int,
    };

    unsafe {
        *version = hdr.version;

        *ty = match hdr.ty {
            Type::Initial            => 1,
            Type::Retry              => 2,
            Type::Handshake          => 3,
            Type::ZeroRTT            => 4,
            Type::Application        => 5,
            Type::VersionNegotiation => 6,
        };

        if *dcid_len < hdr.dcid.len() {
            return -1;
        }

        let dcid = slice::from_raw_parts_mut(dcid, *dcid_len);
        let dcid = &mut dcid[..hdr.dcid.len()];
        dcid.copy_from_slice(&hdr.dcid);

        *dcid_len = hdr.dcid.len();
    }

    0
}

#[no_mangle]
pub extern fn quiche_accept(scid: *const u8, scid_len: usize,
                            config: &mut Config) -> *mut Connection {
    let scid = unsafe { slice::from_raw_parts(scid, scid_len) };

    match accept(scid, config) {
        Ok(c) => Box::into_raw(c),

        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub extern fn quiche_connect(server_name: *const c_char, scid: *const u8,
                             scid_len: usize, config: &mut Config)
                                                -> *mut Connection {
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
pub extern fn quiche_conn_recv(conn: &mut Connection, buf: *mut u8,
                               buf_len: usize) -> ssize_t {
    let buf = unsafe { slice::from_raw_parts_mut(buf, buf_len) };

    match conn.recv(buf) {
        Ok(v) => v as ssize_t,

        Err(e) => e.to_c(),
    }
}

#[no_mangle]
pub extern fn quiche_conn_send(conn: &mut Connection, out: *mut u8,
                               out_len: usize) -> ssize_t {
    let out = unsafe { slice::from_raw_parts_mut(out, out_len) };

    match conn.send(out) {
        Ok(v) => v as ssize_t,

        Err(e) => e.to_c(),
    }
}

#[no_mangle]
pub extern fn quiche_conn_stream_recv(conn: &mut Connection, stream_id: u64)
                                                        -> *const RangeBuf {
    match conn.stream_recv(stream_id) {
        Ok(b) => Box::into_raw(Box::new(b)),

        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub extern fn quiche_conn_stream_send(conn: &mut Connection, stream_id: u64,
                                      buf: *const u8, buf_len: usize, fin: bool)
                                                            -> ssize_t {
    let buf = unsafe { slice::from_raw_parts(buf, buf_len) };

    match conn.stream_send(stream_id, buf, fin) {
        Ok(v) => v as ssize_t,

        Err(e) => e.to_c(),
    }
}

#[no_mangle]
pub extern fn quiche_rangebuf_data(b: &mut RangeBuf) -> *const u8 {
    (&b).as_ptr()
}

#[no_mangle]
pub extern fn quiche_rangebuf_len(b: &mut RangeBuf) -> usize {
    b.len()
}

#[no_mangle]
pub extern fn quiche_rangebuf_fin(b: &mut RangeBuf) -> bool {
    b.fin()
}

#[no_mangle]
pub extern fn quiche_rangebuf_free(b: *mut RangeBuf) {
    unsafe { Box::from_raw(b) };
}

#[no_mangle]
pub extern fn quiche_conn_readable(conn: &mut Connection) -> *mut Readable {
    let iter = conn.readable();
    Box::into_raw(Box::new(iter))
}

#[no_mangle]
pub extern fn quiche_readable_next(iter: &mut Readable, stream_id: *mut u64) -> bool {
    if let Some(v) = iter.next() {
        unsafe { *stream_id = v };
        return true;
    }

    false
}

#[no_mangle]
pub extern fn quiche_readable_free(i: *mut Readable) {
    unsafe { Box::from_raw(i) };
}

#[no_mangle]
pub extern fn quiche_conn_close(conn: &mut Connection, app: bool, err: u16,
                                reason: *const u8, reason_len: usize) -> c_int {
    let reason = unsafe { slice::from_raw_parts(reason, reason_len) };

    match conn.close(app, err, reason) {
        Ok(_) => 0,

        Err(e) => e.to_c() as c_int,
    }
}

#[no_mangle]
pub extern fn quiche_conn_timeout_as_nanos(conn: &mut Connection) -> u64 {
    match conn.timeout() {
        Some(timeout) => timeout.as_secs() * 1_000_000_000 +
                         u64::from(timeout.subsec_nanos()),

        None => std::u64::MAX,
    }
}

#[no_mangle]
pub extern fn quiche_conn_on_timeout(conn: &mut Connection) {
    conn.on_timeout()
}

#[no_mangle]
pub extern fn quiche_conn_is_established(conn: &mut Connection) -> bool {
    conn.is_established()
}

#[no_mangle]
pub extern fn quiche_conn_is_closed(conn: &mut Connection) -> bool {
    conn.is_closed()
}

#[no_mangle]
pub extern fn quiche_conn_free(conn: *mut Connection) {
    unsafe { Box::from_raw(conn) };
}
