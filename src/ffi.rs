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
use std::sync::atomic;

use std::net::SocketAddr;

#[cfg(unix)]
use std::os::unix::io::FromRawFd;

use libc::c_char;
use libc::c_int;
use libc::c_void;
use libc::size_t;
use libc::sockaddr;
use libc::ssize_t;
use libc::timespec;

#[cfg(not(windows))]
use libc::sockaddr_in;
#[cfg(windows)]
use winapi::shared::ws2def::SOCKADDR_IN as sockaddr_in;

#[cfg(not(windows))]
use libc::sockaddr_in6;
#[cfg(windows)]
use winapi::shared::ws2ipdef::SOCKADDR_IN6_LH as sockaddr_in6;

#[cfg(not(windows))]
use libc::sockaddr_storage;
#[cfg(windows)]
use winapi::shared::ws2def::SOCKADDR_STORAGE_LH as sockaddr_storage;

#[cfg(windows)]
use libc::c_int as socklen_t;
#[cfg(not(windows))]
use libc::socklen_t;

#[cfg(not(windows))]
use libc::AF_INET;
#[cfg(windows)]
use winapi::shared::ws2def::AF_INET;

#[cfg(not(windows))]
use libc::AF_INET6;
#[cfg(windows)]
use winapi::shared::ws2def::AF_INET6;

use crate::*;

#[no_mangle]
pub extern fn quiche_version() -> *const u8 {
    static VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "\0");
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
) -> c_int {
    let argp = atomic::AtomicPtr::new(argp);
    let logger = Box::new(Logger { cb, argp });

    if log::set_boxed_logger(logger).is_err() {
        return -1;
    }

    log::set_max_level(log::LevelFilter::Trace);

    0
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
pub extern fn quiche_config_load_verify_locations_from_file(
    config: &mut Config, path: *const c_char,
) -> c_int {
    let path = unsafe { ffi::CStr::from_ptr(path).to_str().unwrap() };

    match config.load_verify_locations_from_file(path) {
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
pub extern fn quiche_config_enable_early_data(config: &mut Config) {
    config.enable_early_data();
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
pub extern fn quiche_config_set_max_idle_timeout(config: &mut Config, v: u64) {
    config.set_max_idle_timeout(v);
}

#[no_mangle]
pub extern fn quiche_config_set_max_recv_udp_payload_size(
    config: &mut Config, v: size_t,
) {
    config.set_max_recv_udp_payload_size(v);
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
pub extern fn quiche_config_set_disable_active_migration(
    config: &mut Config, v: bool,
) {
    config.set_disable_active_migration(v);
}

#[no_mangle]
pub extern fn quiche_config_set_cc_algorithm_name(
    config: &mut Config, name: *const c_char,
) -> c_int {
    let name = unsafe { ffi::CStr::from_ptr(name).to_str().unwrap() };
    match config.set_cc_algorithm_name(name) {
        Ok(_) => 0,

        Err(e) => e.to_c() as c_int,
    }
}

#[no_mangle]
pub extern fn quiche_config_set_cc_algorithm(
    config: &mut Config, algo: CongestionControlAlgorithm,
) {
    config.set_cc_algorithm(algo);
}

#[no_mangle]
pub extern fn quiche_config_enable_hystart(config: &mut Config, v: bool) {
    config.enable_hystart(v);
}

#[no_mangle]
pub extern fn quiche_config_enable_dgram(
    config: &mut Config, enabled: bool, recv_queue_len: size_t,
    send_queue_len: size_t,
) {
    config.enable_dgram(enabled, recv_queue_len, send_queue_len);
}

#[no_mangle]
pub extern fn quiche_config_set_max_send_udp_payload_size(
    config: &mut Config, v: size_t,
) {
    config.set_max_send_udp_payload_size(v);
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
        Ok(v) => v,

        Err(e) => return e.to_c() as c_int,
    };

    unsafe {
        *version = hdr.version;

        *ty = match hdr.ty {
            Type::Initial => 1,
            Type::Retry => 2,
            Type::Handshake => 3,
            Type::ZeroRTT => 4,
            Type::Short => 5,
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
    from: &sockaddr, from_len: socklen_t, config: &mut Config,
) -> *mut Connection {
    let scid = unsafe { slice::from_raw_parts(scid, scid_len) };
    let scid = ConnectionId::from_ref(scid);

    let odcid = if !odcid.is_null() && odcid_len > 0 {
        Some(ConnectionId::from_ref(unsafe {
            slice::from_raw_parts(odcid, odcid_len)
        }))
    } else {
        None
    };

    let from = std_addr_from_c(from, from_len);

    match accept(&scid, odcid.as_ref(), from, config) {
        Ok(c) => Box::into_raw(Pin::into_inner(c)),

        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub extern fn quiche_connect(
    server_name: *const c_char, scid: *const u8, scid_len: size_t, to: &sockaddr,
    to_len: socklen_t, config: &mut Config,
) -> *mut Connection {
    let server_name = if server_name.is_null() {
        None
    } else {
        Some(unsafe { ffi::CStr::from_ptr(server_name).to_str().unwrap() })
    };

    let scid = unsafe { slice::from_raw_parts(scid, scid_len) };
    let scid = ConnectionId::from_ref(scid);

    let to = std_addr_from_c(to, to_len);

    match connect(server_name, &scid, to, config) {
        Ok(c) => Box::into_raw(Pin::into_inner(c)),

        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub extern fn quiche_negotiate_version(
    scid: *const u8, scid_len: size_t, dcid: *const u8, dcid_len: size_t,
    out: *mut u8, out_len: size_t,
) -> ssize_t {
    let scid = unsafe { slice::from_raw_parts(scid, scid_len) };
    let scid = ConnectionId::from_ref(scid);

    let dcid = unsafe { slice::from_raw_parts(dcid, dcid_len) };
    let dcid = ConnectionId::from_ref(dcid);

    let out = unsafe { slice::from_raw_parts_mut(out, out_len) };

    match negotiate_version(&scid, &dcid, out) {
        Ok(v) => v as ssize_t,

        Err(e) => e.to_c(),
    }
}

#[no_mangle]
pub extern fn quiche_version_is_supported(version: u32) -> bool {
    version_is_supported(version)
}

#[no_mangle]
pub extern fn quiche_retry(
    scid: *const u8, scid_len: size_t, dcid: *const u8, dcid_len: size_t,
    new_scid: *const u8, new_scid_len: size_t, token: *const u8,
    token_len: size_t, version: u32, out: *mut u8, out_len: size_t,
) -> ssize_t {
    let scid = unsafe { slice::from_raw_parts(scid, scid_len) };
    let scid = ConnectionId::from_ref(scid);

    let dcid = unsafe { slice::from_raw_parts(dcid, dcid_len) };
    let dcid = ConnectionId::from_ref(dcid);

    let new_scid = unsafe { slice::from_raw_parts(new_scid, new_scid_len) };
    let new_scid = ConnectionId::from_ref(new_scid);

    let token = unsafe { slice::from_raw_parts(token, token_len) };
    let out = unsafe { slice::from_raw_parts_mut(out, out_len) };

    match retry(&scid, &dcid, &new_scid, token, version, out) {
        Ok(v) => v as ssize_t,

        Err(e) => e.to_c(),
    }
}

#[no_mangle]
pub extern fn quiche_conn_new_with_tls(
    scid: *const u8, scid_len: size_t, odcid: *const u8, odcid_len: size_t,
    peer: &sockaddr, peer_len: socklen_t, config: &mut Config, ssl: *mut c_void,
    is_server: bool,
) -> *mut Connection {
    let scid = unsafe { slice::from_raw_parts(scid, scid_len) };
    let scid = ConnectionId::from_ref(scid);

    let odcid = if !odcid.is_null() && odcid_len > 0 {
        Some(ConnectionId::from_ref(unsafe {
            slice::from_raw_parts(odcid, odcid_len)
        }))
    } else {
        None
    };

    let peer = std_addr_from_c(peer, peer_len);

    let tls = unsafe { tls::Handshake::from_ptr(ssl) };

    match Connection::with_tls(
        &scid,
        odcid.as_ref(),
        peer,
        config,
        tls,
        is_server,
    ) {
        Ok(c) => Box::into_raw(Pin::into_inner(c)),

        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub extern fn quiche_conn_set_keylog_path(
    conn: &mut Connection, path: *const c_char,
) -> bool {
    let filename = unsafe { ffi::CStr::from_ptr(path).to_str().unwrap() };

    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(filename);

    let writer = match file {
        Ok(f) => std::io::BufWriter::new(f),

        Err(_) => return false,
    };

    conn.set_keylog(Box::new(writer));

    true
}

#[no_mangle]
#[cfg(unix)]
pub extern fn quiche_conn_set_keylog_fd(conn: &mut Connection, fd: c_int) {
    let f = unsafe { std::fs::File::from_raw_fd(fd) };
    let writer = std::io::BufWriter::new(f);

    conn.set_keylog(Box::new(writer));
}

#[no_mangle]
#[cfg(feature = "qlog")]
pub extern fn quiche_conn_set_qlog_path(
    conn: &mut Connection, path: *const c_char, log_title: *const c_char,
    log_desc: *const c_char,
) -> bool {
    let filename = unsafe { ffi::CStr::from_ptr(path).to_str().unwrap() };

    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(filename);

    let writer = match file {
        Ok(f) => std::io::BufWriter::new(f),

        Err(_) => return false,
    };

    let title = unsafe { ffi::CStr::from_ptr(log_title).to_str().unwrap() };
    let description = unsafe { ffi::CStr::from_ptr(log_desc).to_str().unwrap() };

    conn.set_qlog(
        Box::new(writer),
        title.to_string(),
        format!("{} id={}", description, conn.trace_id),
    );

    true
}

#[no_mangle]
#[cfg(all(unix, feature = "qlog"))]
pub extern fn quiche_conn_set_qlog_fd(
    conn: &mut Connection, fd: c_int, log_title: *const c_char,
    log_desc: *const c_char,
) {
    let f = unsafe { std::fs::File::from_raw_fd(fd) };
    let writer = std::io::BufWriter::new(f);

    let title = unsafe { ffi::CStr::from_ptr(log_title).to_str().unwrap() };
    let description = unsafe { ffi::CStr::from_ptr(log_desc).to_str().unwrap() };

    conn.set_qlog(
        Box::new(writer),
        title.to_string(),
        format!("{} id={}", description, conn.trace_id),
    );
}

#[no_mangle]
pub extern fn quiche_conn_set_session(
    conn: &mut Connection, buf: *const u8, buf_len: size_t,
) -> c_int {
    let buf = unsafe { slice::from_raw_parts(buf, buf_len) };

    match conn.set_session(buf) {
        Ok(_) => 0,

        Err(e) => e.to_c() as c_int,
    }
}

#[repr(C)]
pub struct RecvInfo<'a> {
    from: &'a sockaddr,
    from_len: socklen_t,
}

impl<'a> From<&RecvInfo<'a>> for crate::RecvInfo {
    fn from(info: &RecvInfo) -> crate::RecvInfo {
        crate::RecvInfo {
            from: std_addr_from_c(info.from, info.from_len),
        }
    }
}

#[no_mangle]
pub extern fn quiche_conn_recv(
    conn: &mut Connection, buf: *mut u8, buf_len: size_t, info: &RecvInfo,
) -> ssize_t {
    if buf_len > <ssize_t>::max_value() as usize {
        panic!("The provided buffer is too large");
    }

    let buf = unsafe { slice::from_raw_parts_mut(buf, buf_len) };

    match conn.recv(buf, info.into()) {
        Ok(v) => v as ssize_t,

        Err(e) => e.to_c(),
    }
}

#[repr(C)]
pub struct SendInfo {
    to: sockaddr_storage,
    to_len: socklen_t,

    at: timespec,
}

#[no_mangle]
pub extern fn quiche_conn_send(
    conn: &mut Connection, out: *mut u8, out_len: size_t, out_info: &mut SendInfo,
) -> ssize_t {
    if out_len > <ssize_t>::max_value() as usize {
        panic!("The provided buffer is too large");
    }

    let out = unsafe { slice::from_raw_parts_mut(out, out_len) };

    match conn.send(out) {
        Ok((v, info)) => {
            out_info.to_len = std_addr_to_c(&info.to, &mut out_info.to);

            std_time_to_c(&info.at, &mut out_info.at);

            v as ssize_t
        },

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
pub extern fn quiche_conn_stream_priority(
    conn: &mut Connection, stream_id: u64, urgency: u8, incremental: bool,
) -> c_int {
    match conn.stream_priority(stream_id, urgency, incremental) {
        Ok(_) => 0,

        Err(e) => e.to_c() as c_int,
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
pub extern fn quiche_conn_stream_capacity(
    conn: &mut Connection, stream_id: u64,
) -> ssize_t {
    match conn.stream_capacity(stream_id) {
        Ok(v) => v as ssize_t,

        Err(e) => e.to_c(),
    }
}

#[no_mangle]
pub extern fn quiche_conn_stream_readable(
    conn: &mut Connection, stream_id: u64,
) -> bool {
    conn.stream_readable(stream_id)
}

#[no_mangle]
pub extern fn quiche_conn_stream_finished(
    conn: &mut Connection, stream_id: u64,
) -> bool {
    conn.stream_finished(stream_id)
}

#[no_mangle]
pub extern fn quiche_conn_readable(conn: &Connection) -> *mut StreamIter {
    Box::into_raw(Box::new(conn.readable()))
}

#[no_mangle]
pub extern fn quiche_conn_writable(conn: &Connection) -> *mut StreamIter {
    Box::into_raw(Box::new(conn.writable()))
}

#[no_mangle]
pub extern fn quiche_conn_max_send_udp_payload_size(conn: &Connection) -> usize {
    conn.max_send_udp_payload_size()
}

#[no_mangle]
pub extern fn quiche_conn_is_readable(conn: &Connection) -> bool {
    conn.is_readable()
}

struct AppData(*mut c_void);
unsafe impl Send for AppData {}
unsafe impl Sync for AppData {}

#[no_mangle]
pub extern fn quiche_conn_stream_init_application_data(
    conn: &mut Connection, stream_id: u64, data: *mut c_void,
) -> c_int {
    match conn.stream_init_application_data(stream_id, AppData(data)) {
        Ok(_) => 0,

        Err(e) => e.to_c() as c_int,
    }
}

#[no_mangle]
pub extern fn quiche_conn_stream_application_data(
    conn: &mut Connection, stream_id: u64,
) -> *mut c_void {
    match conn.stream_application_data(stream_id) {
        Some(v) => v.downcast_mut::<AppData>().unwrap().0,

        None => ptr::null_mut(),
    }
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
pub extern fn quiche_conn_timeout_as_millis(conn: &mut Connection) -> u64 {
    match conn.timeout() {
        Some(timeout) => timeout.as_millis() as u64,

        None => std::u64::MAX,
    }
}

#[no_mangle]
pub extern fn quiche_conn_on_timeout(conn: &mut Connection) {
    conn.on_timeout()
}

#[no_mangle]
pub extern fn quiche_conn_trace_id(
    conn: &mut Connection, out: &mut *const u8, out_len: &mut size_t,
) {
    let trace_id = conn.trace_id();

    *out = trace_id.as_ptr();
    *out_len = trace_id.len();
}

#[no_mangle]
pub extern fn quiche_conn_source_id(
    conn: &mut Connection, out: &mut *const u8, out_len: &mut size_t,
) {
    let conn_id = conn.source_id();
    let id = conn_id.as_ref();
    *out = id.as_ptr();
    *out_len = id.len();
}

#[no_mangle]
pub extern fn quiche_conn_destination_id(
    conn: &mut Connection, out: &mut *const u8, out_len: &mut size_t,
) {
    let conn_id = conn.destination_id();
    let id = conn_id.as_ref();

    *out = id.as_ptr();
    *out_len = id.len();
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
pub extern fn quiche_conn_session(
    conn: &mut Connection, out: &mut *const u8, out_len: &mut size_t,
) {
    match conn.session() {
        Some(session) => {
            *out = session.as_ptr();
            *out_len = session.len();
        },

        None => *out_len = 0,
    }
}

#[no_mangle]
pub extern fn quiche_conn_is_established(conn: &mut Connection) -> bool {
    conn.is_established()
}

#[no_mangle]
pub extern fn quiche_conn_is_in_early_data(conn: &mut Connection) -> bool {
    conn.is_in_early_data()
}

#[no_mangle]
pub extern fn quiche_conn_is_draining(conn: &mut Connection) -> bool {
    conn.is_draining()
}

#[no_mangle]
pub extern fn quiche_conn_is_closed(conn: &mut Connection) -> bool {
    conn.is_closed()
}

#[no_mangle]
pub extern fn quiche_conn_peer_error(
    conn: &mut Connection, is_app: *mut bool, error_code: *mut u64,
    reason: &mut *const u8, reason_len: &mut size_t,
) -> bool {
    match &conn.peer_error {
        Some(conn_err) => unsafe {
            *is_app = conn_err.is_app;
            *error_code = conn_err.error_code;
            *reason = conn_err.reason.as_ptr();
            *reason_len = conn_err.reason.len();

            true
        },

        None => false,
    }
}

#[no_mangle]
pub extern fn quiche_stream_iter_next(
    iter: &mut StreamIter, stream_id: *mut u64,
) -> bool {
    if let Some(v) = iter.next() {
        unsafe { *stream_id = v };
        return true;
    }

    false
}

#[no_mangle]
pub extern fn quiche_stream_iter_free(iter: *mut StreamIter) {
    unsafe { Box::from_raw(iter) };
}

#[repr(C)]
pub struct Stats {
    recv: usize,
    sent: usize,
    lost: usize,
    retrans: usize,
    rtt: u64,
    cwnd: usize,
    sent_bytes: u64,
    lost_bytes: u64,
    recv_bytes: u64,
    stream_retrans_bytes: u64,
    pmtu: usize,
    delivery_rate: u64,
    peer_max_idle_timeout: u64,
    peer_max_udp_payload_size: u64,
    peer_initial_max_data: u64,
    peer_initial_max_stream_data_bidi_local: u64,
    peer_initial_max_stream_data_bidi_remote: u64,
    peer_initial_max_stream_data_uni: u64,
    peer_initial_max_streams_bidi: u64,
    peer_initial_max_streams_uni: u64,
    peer_ack_delay_exponent: u64,
    peer_max_ack_delay: u64,
    peer_disable_active_migration: bool,
    peer_active_conn_id_limit: u64,
    peer_max_datagram_frame_size: ssize_t,
}

#[no_mangle]
pub extern fn quiche_conn_stats(conn: &Connection, out: &mut Stats) {
    let stats = conn.stats();

    out.recv = stats.recv;
    out.sent = stats.sent;
    out.lost = stats.lost;
    out.retrans = stats.retrans;
    out.rtt = stats.rtt.as_nanos() as u64;
    out.cwnd = stats.cwnd;
    out.sent_bytes = stats.sent_bytes;
    out.lost_bytes = stats.lost_bytes;
    out.recv_bytes = stats.recv_bytes;
    out.stream_retrans_bytes = stats.stream_retrans_bytes;
    out.pmtu = stats.pmtu;
    out.delivery_rate = stats.delivery_rate;
    out.peer_max_idle_timeout = stats.peer_max_idle_timeout;
    out.peer_max_udp_payload_size = stats.peer_max_udp_payload_size;
    out.peer_initial_max_data = stats.peer_initial_max_data;
    out.peer_initial_max_stream_data_bidi_local =
        stats.peer_initial_max_stream_data_bidi_local;
    out.peer_initial_max_stream_data_bidi_remote =
        stats.peer_initial_max_stream_data_bidi_remote;
    out.peer_initial_max_stream_data_uni = stats.peer_initial_max_stream_data_uni;
    out.peer_initial_max_streams_bidi = stats.peer_initial_max_streams_bidi;
    out.peer_initial_max_streams_uni = stats.peer_initial_max_streams_uni;
    out.peer_ack_delay_exponent = stats.peer_ack_delay_exponent;
    out.peer_max_ack_delay = stats.peer_max_ack_delay;
    out.peer_disable_active_migration = stats.peer_disable_active_migration;
    out.peer_active_conn_id_limit = stats.peer_active_conn_id_limit;
    out.peer_max_datagram_frame_size = match stats.peer_max_datagram_frame_size {
        None => Error::Done.to_c(),

        Some(v) => v as ssize_t,
    }
}

#[no_mangle]
pub extern fn quiche_conn_dgram_max_writable_len(conn: &Connection) -> ssize_t {
    match conn.dgram_max_writable_len() {
        None => Error::Done.to_c(),

        Some(v) => v as ssize_t,
    }
}

#[no_mangle]
pub extern fn quiche_conn_dgram_recv_front_len(conn: &Connection) -> ssize_t {
    match conn.dgram_recv_front_len() {
        None => Error::Done.to_c(),

        Some(v) => v as ssize_t,
    }
}

#[no_mangle]
pub extern fn quiche_conn_dgram_recv_queue_len(conn: &Connection) -> ssize_t {
    conn.dgram_recv_queue_len() as ssize_t
}

#[no_mangle]
pub extern fn quiche_conn_dgram_recv_queue_byte_size(
    conn: &Connection,
) -> ssize_t {
    conn.dgram_recv_queue_byte_size() as ssize_t
}

#[no_mangle]
pub extern fn quiche_conn_dgram_send_queue_len(conn: &Connection) -> ssize_t {
    conn.dgram_send_queue_len() as ssize_t
}

#[no_mangle]
pub extern fn quiche_conn_dgram_send_queue_byte_size(
    conn: &Connection,
) -> ssize_t {
    conn.dgram_send_queue_byte_size() as ssize_t
}

#[no_mangle]
pub extern fn quiche_conn_dgram_send(
    conn: &mut Connection, buf: *const u8, buf_len: size_t,
) -> ssize_t {
    if buf_len > <ssize_t>::max_value() as usize {
        panic!("The provided buffer is too large");
    }

    let buf = unsafe { slice::from_raw_parts(buf, buf_len) };

    match conn.dgram_send(buf) {
        Ok(_) => buf_len as ssize_t,

        Err(e) => e.to_c(),
    }
}

#[no_mangle]
pub extern fn quiche_conn_dgram_recv(
    conn: &mut Connection, out: *mut u8, out_len: size_t,
) -> ssize_t {
    if out_len > <ssize_t>::max_value() as usize {
        panic!("The provided buffer is too large");
    }

    let out = unsafe { slice::from_raw_parts_mut(out, out_len) };

    let out_len = match conn.dgram_recv(out) {
        Ok(v) => v,

        Err(e) => return e.to_c(),
    };

    out_len as ssize_t
}

#[no_mangle]
pub extern fn quiche_conn_dgram_purge_outgoing(
    conn: &mut Connection, f: extern fn(*const u8, size_t) -> bool,
) {
    conn.dgram_purge_outgoing(|d: &[u8]| -> bool {
        let ptr: *const u8 = d.as_ptr();
        let len: size_t = d.len();

        f(ptr, len)
    });
}

#[no_mangle]
pub extern fn quiche_conn_free(conn: *mut Connection) {
    unsafe { Box::from_raw(conn) };
}

#[no_mangle]
pub extern fn quiche_conn_peer_streams_left_bidi(conn: &mut Connection) -> u64 {
    conn.peer_streams_left_bidi()
}

#[no_mangle]
pub extern fn quiche_conn_peer_streams_left_uni(conn: &mut Connection) -> u64 {
    conn.peer_streams_left_uni()
}

fn std_addr_from_c(addr: &sockaddr, addr_len: socklen_t) -> SocketAddr {
    unsafe {
        match addr.sa_family as i32 {
            AF_INET => {
                assert!(addr_len as usize == std::mem::size_of::<sockaddr_in>());

                SocketAddr::V4(
                    *(addr as *const _ as *const sockaddr_in as *const _),
                )
            },

            AF_INET6 => {
                assert!(addr_len as usize == std::mem::size_of::<sockaddr_in6>());

                SocketAddr::V6(
                    *(addr as *const _ as *const sockaddr_in6 as *const _),
                )
            },

            _ => unimplemented!("unsupported address type"),
        }
    }
}

fn std_addr_to_c(addr: &SocketAddr, out: &mut sockaddr_storage) -> socklen_t {
    unsafe {
        match addr {
            SocketAddr::V4(addr) => {
                let sa_len = std::mem::size_of::<sockaddr_in>();

                let src = addr as *const _ as *const u8;
                let dst = out as *mut _ as *mut u8;

                std::ptr::copy_nonoverlapping(src, dst, sa_len);

                sa_len as socklen_t
            },

            SocketAddr::V6(addr) => {
                let sa_len = std::mem::size_of::<sockaddr_in6>();

                let src = addr as *const _ as *const u8;
                let dst = out as *mut _ as *mut u8;

                std::ptr::copy_nonoverlapping(src, dst, sa_len);

                sa_len as socklen_t
            },
        }
    }
}

#[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "windows")))]
fn std_time_to_c(time: &std::time::Instant, out: &mut timespec) {
    unsafe {
        ptr::copy_nonoverlapping(time as *const _ as *const timespec, out, 1)
    }
}

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "windows"))]
fn std_time_to_c(_time: &std::time::Instant, out: &mut timespec) {
    // TODO: implement Instant conversion for systems that don't use timespec.
    out.tv_sec = 0;
    out.tv_nsec = 0;
}
