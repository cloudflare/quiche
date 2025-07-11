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

use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddrV4;
use std::net::SocketAddrV6;

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
use libc::AF_INET;
#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::AF_INET;

#[cfg(not(windows))]
use libc::AF_INET6;
#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::AF_INET6;

#[cfg(not(windows))]
use libc::in_addr;
#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::IN_ADDR as in_addr;

#[cfg(not(windows))]
use libc::in6_addr;
#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::IN6_ADDR as in6_addr;

#[cfg(not(windows))]
use libc::sa_family_t;
#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::ADDRESS_FAMILY as sa_family_t;

#[cfg(not(windows))]
use libc::sockaddr_in;
#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::SOCKADDR_IN as sockaddr_in;

#[cfg(not(windows))]
use libc::sockaddr_in6;
#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::SOCKADDR_IN6 as sockaddr_in6;

#[cfg(not(windows))]
use libc::sockaddr_storage;
#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::SOCKADDR_STORAGE as sockaddr_storage;

#[cfg(windows)]
use libc::c_int as socklen_t;
#[cfg(not(windows))]
use libc::socklen_t;

#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::IN6_ADDR_0;
#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::IN_ADDR_0;
#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::SOCKADDR_IN6_0;

use crate::*;

#[no_mangle]
pub extern "C" fn quiche_version() -> *const u8 {
    static VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "\0");
    VERSION.as_ptr()
}

struct Logger {
    cb: extern "C" fn(line: *const u8, argp: *mut c_void),
    argp: atomic::AtomicPtr<c_void>,
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
pub extern "C" fn quiche_enable_debug_logging(
    cb: extern "C" fn(line: *const u8, argp: *mut c_void), argp: *mut c_void,
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
pub extern "C" fn quiche_config_new(version: u32) -> *mut Config {
    match Config::new(version) {
        Ok(c) => Box::into_raw(Box::new(c)),

        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn quiche_config_load_cert_chain_from_pem_file(
    config: &mut Config, path: *const c_char,
) -> c_int {
    let path = unsafe { ffi::CStr::from_ptr(path).to_str().unwrap() };

    match config.load_cert_chain_from_pem_file(path) {
        Ok(_) => 0,

        Err(e) => e.to_c() as c_int,
    }
}

#[no_mangle]
pub extern "C" fn quiche_config_load_priv_key_from_pem_file(
    config: &mut Config, path: *const c_char,
) -> c_int {
    let path = unsafe { ffi::CStr::from_ptr(path).to_str().unwrap() };

    match config.load_priv_key_from_pem_file(path) {
        Ok(_) => 0,

        Err(e) => e.to_c() as c_int,
    }
}

#[no_mangle]
pub extern "C" fn quiche_config_load_verify_locations_from_file(
    config: &mut Config, path: *const c_char,
) -> c_int {
    let path = unsafe { ffi::CStr::from_ptr(path).to_str().unwrap() };

    match config.load_verify_locations_from_file(path) {
        Ok(_) => 0,

        Err(e) => e.to_c() as c_int,
    }
}

#[no_mangle]
pub extern "C" fn quiche_config_load_verify_locations_from_directory(
    config: &mut Config, path: *const c_char,
) -> c_int {
    let path = unsafe { ffi::CStr::from_ptr(path).to_str().unwrap() };

    match config.load_verify_locations_from_directory(path) {
        Ok(_) => 0,

        Err(e) => e.to_c() as c_int,
    }
}

#[no_mangle]
pub extern "C" fn quiche_config_verify_peer(config: &mut Config, v: bool) {
    config.verify_peer(v);
}

#[no_mangle]
pub extern "C" fn quiche_config_grease(config: &mut Config, v: bool) {
    config.grease(v);
}

#[no_mangle]
pub extern "C" fn quiche_config_discover_pmtu(config: &mut Config, v: bool) {
    config.discover_pmtu(v);
}

#[no_mangle]
pub extern "C" fn quiche_config_log_keys(config: &mut Config) {
    config.log_keys();
}

#[no_mangle]
pub extern "C" fn quiche_config_enable_early_data(config: &mut Config) {
    config.enable_early_data();
}

#[no_mangle]
/// Corresponds to the `Config::set_application_protos_wire_format` Rust
/// function.
pub extern "C" fn quiche_config_set_application_protos(
    config: &mut Config, protos: *const u8, protos_len: size_t,
) -> c_int {
    let protos = unsafe { slice::from_raw_parts(protos, protos_len) };

    match config.set_application_protos_wire_format(protos) {
        Ok(_) => 0,

        Err(e) => e.to_c() as c_int,
    }
}

#[no_mangle]
pub extern "C" fn quiche_config_set_max_amplification_factor(
    config: &mut Config, v: usize,
) {
    config.set_max_amplification_factor(v);
}

#[no_mangle]
pub extern "C" fn quiche_config_set_max_idle_timeout(
    config: &mut Config, v: u64,
) {
    config.set_max_idle_timeout(v);
}

#[no_mangle]
pub extern "C" fn quiche_config_set_max_recv_udp_payload_size(
    config: &mut Config, v: size_t,
) {
    config.set_max_recv_udp_payload_size(v);
}

#[no_mangle]
pub extern "C" fn quiche_config_set_initial_max_data(
    config: &mut Config, v: u64,
) {
    config.set_initial_max_data(v);
}

#[no_mangle]
pub extern "C" fn quiche_config_set_initial_max_stream_data_bidi_local(
    config: &mut Config, v: u64,
) {
    config.set_initial_max_stream_data_bidi_local(v);
}

#[no_mangle]
pub extern "C" fn quiche_config_set_initial_max_stream_data_bidi_remote(
    config: &mut Config, v: u64,
) {
    config.set_initial_max_stream_data_bidi_remote(v);
}

#[no_mangle]
pub extern "C" fn quiche_config_set_initial_max_stream_data_uni(
    config: &mut Config, v: u64,
) {
    config.set_initial_max_stream_data_uni(v);
}

#[no_mangle]
pub extern "C" fn quiche_config_set_initial_max_streams_bidi(
    config: &mut Config, v: u64,
) {
    config.set_initial_max_streams_bidi(v);
}

#[no_mangle]
pub extern "C" fn quiche_config_set_initial_max_streams_uni(
    config: &mut Config, v: u64,
) {
    config.set_initial_max_streams_uni(v);
}

#[no_mangle]
pub extern "C" fn quiche_config_set_ack_delay_exponent(
    config: &mut Config, v: u64,
) {
    config.set_ack_delay_exponent(v);
}

#[no_mangle]
pub extern "C" fn quiche_config_set_max_ack_delay(config: &mut Config, v: u64) {
    config.set_max_ack_delay(v);
}

#[no_mangle]
pub extern "C" fn quiche_config_set_disable_active_migration(
    config: &mut Config, v: bool,
) {
    config.set_disable_active_migration(v);
}

#[no_mangle]
pub extern "C" fn quiche_config_set_cc_algorithm_name(
    config: &mut Config, name: *const c_char,
) -> c_int {
    let name = unsafe { ffi::CStr::from_ptr(name).to_str().unwrap() };
    match config.set_cc_algorithm_name(name) {
        Ok(_) => 0,

        Err(e) => e.to_c() as c_int,
    }
}

#[no_mangle]
pub extern "C" fn quiche_config_set_cc_algorithm(
    config: &mut Config, algo: CongestionControlAlgorithm,
) {
    config.set_cc_algorithm(algo);
}

#[no_mangle]
pub extern "C" fn quiche_config_set_initial_congestion_window_packets(
    config: &mut Config, packets: size_t,
) {
    config.set_initial_congestion_window_packets(packets);
}

#[no_mangle]
pub extern "C" fn quiche_config_enable_hystart(config: &mut Config, v: bool) {
    config.enable_hystart(v);
}

#[no_mangle]
pub extern "C" fn quiche_config_enable_pacing(config: &mut Config, v: bool) {
    config.enable_pacing(v);
}

#[no_mangle]
pub extern "C" fn quiche_config_set_max_pacing_rate(config: &mut Config, v: u64) {
    config.set_max_pacing_rate(v);
}

#[no_mangle]
pub extern "C" fn quiche_config_enable_dgram(
    config: &mut Config, enabled: bool, recv_queue_len: size_t,
    send_queue_len: size_t,
) {
    config.enable_dgram(enabled, recv_queue_len, send_queue_len);
}

#[no_mangle]
pub extern "C" fn quiche_config_set_max_send_udp_payload_size(
    config: &mut Config, v: size_t,
) {
    config.set_max_send_udp_payload_size(v);
}

#[no_mangle]
pub extern "C" fn quiche_config_set_max_connection_window(
    config: &mut Config, v: u64,
) {
    config.set_max_connection_window(v);
}

#[no_mangle]
pub extern "C" fn quiche_config_set_max_stream_window(
    config: &mut Config, v: u64,
) {
    config.set_max_stream_window(v);
}

#[no_mangle]
pub extern "C" fn quiche_config_set_active_connection_id_limit(
    config: &mut Config, v: u64,
) {
    config.set_active_connection_id_limit(v);
}

#[no_mangle]
pub extern "C" fn quiche_config_set_stateless_reset_token(
    config: &mut Config, v: *const u8,
) {
    let reset_token = unsafe { slice::from_raw_parts(v, 16) };
    let reset_token = match reset_token.try_into() {
        Ok(rt) => rt,
        Err(_) => unreachable!(),
    };
    let reset_token = u128::from_be_bytes(reset_token);
    config.set_stateless_reset_token(Some(reset_token));
}

#[no_mangle]
pub extern "C" fn quiche_config_set_disable_dcid_reuse(
    config: &mut Config, v: bool,
) {
    config.set_disable_dcid_reuse(v);
}

#[no_mangle]
pub extern "C" fn quiche_config_set_ticket_key(
    config: &mut Config, key: *const u8, key_len: size_t,
) -> c_int {
    let key = unsafe { slice::from_raw_parts(key, key_len) };

    match config.set_ticket_key(key) {
        Ok(_) => 0,

        Err(e) => e.to_c() as c_int,
    }
}

#[no_mangle]
pub extern "C" fn quiche_config_free(config: *mut Config) {
    drop(unsafe { Box::from_raw(config) });
}

#[no_mangle]
pub extern "C" fn quiche_header_info(
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
pub extern "C" fn quiche_accept(
    scid: *const u8, scid_len: size_t, odcid: *const u8, odcid_len: size_t,
    local: &sockaddr, local_len: socklen_t, peer: &sockaddr, peer_len: socklen_t,
    config: &mut Config,
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

    let local = std_addr_from_c(local, local_len);
    let peer = std_addr_from_c(peer, peer_len);

    match accept(&scid, odcid.as_ref(), local, peer, config) {
        Ok(c) => Box::into_raw(Box::new(c)),

        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn quiche_connect(
    server_name: *const c_char, scid: *const u8, scid_len: size_t,
    local: &sockaddr, local_len: socklen_t, peer: &sockaddr, peer_len: socklen_t,
    config: &mut Config,
) -> *mut Connection {
    let server_name = if server_name.is_null() {
        None
    } else {
        Some(unsafe { ffi::CStr::from_ptr(server_name).to_str().unwrap() })
    };

    let scid = unsafe { slice::from_raw_parts(scid, scid_len) };
    let scid = ConnectionId::from_ref(scid);

    let local = std_addr_from_c(local, local_len);
    let peer = std_addr_from_c(peer, peer_len);

    match connect(server_name, &scid, local, peer, config) {
        Ok(c) => Box::into_raw(Box::new(c)),

        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn quiche_negotiate_version(
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
pub extern "C" fn quiche_version_is_supported(version: u32) -> bool {
    version_is_supported(version)
}

#[no_mangle]
pub extern "C" fn quiche_retry(
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
pub extern "C" fn quiche_conn_new_with_tls(
    scid: *const u8, scid_len: size_t, odcid: *const u8, odcid_len: size_t,
    local: &sockaddr, local_len: socklen_t, peer: &sockaddr, peer_len: socklen_t,
    config: &Config, ssl: *mut c_void, is_server: bool,
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

    let local = std_addr_from_c(local, local_len);
    let peer = std_addr_from_c(peer, peer_len);

    let tls = unsafe { tls::Handshake::from_ptr(ssl) };

    match Connection::with_tls(
        &scid,
        odcid.as_ref(),
        local,
        peer,
        config,
        tls,
        is_server,
    ) {
        Ok(c) => Box::into_raw(Box::new(c)),

        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_set_keylog_path(
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
pub extern "C" fn quiche_conn_set_keylog_fd(conn: &mut Connection, fd: c_int) {
    let f = unsafe { std::fs::File::from_raw_fd(fd) };
    let writer = std::io::BufWriter::new(f);

    conn.set_keylog(Box::new(writer));
}

#[no_mangle]
#[cfg(feature = "qlog")]
pub extern "C" fn quiche_conn_set_qlog_path(
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
pub extern "C" fn quiche_conn_set_qlog_fd(
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
pub extern "C" fn quiche_conn_set_session(
    conn: &mut Connection, buf: *const u8, buf_len: size_t,
) -> c_int {
    let buf = unsafe { slice::from_raw_parts(buf, buf_len) };

    match conn.set_session(buf) {
        Ok(_) => 0,

        Err(e) => e.to_c() as c_int,
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_set_max_idle_timeout(
    conn: &mut Connection, v: u64,
) -> c_int {
    match conn.set_max_idle_timeout(v) {
        Ok(()) => 0,

        Err(e) => e.to_c() as c_int,
    }
}

#[repr(C)]
pub struct RecvInfo<'a> {
    from: &'a sockaddr,
    from_len: socklen_t,
    to: &'a sockaddr,
    to_len: socklen_t,
}

impl From<&RecvInfo<'_>> for crate::RecvInfo {
    fn from(info: &RecvInfo) -> crate::RecvInfo {
        crate::RecvInfo {
            from: std_addr_from_c(info.from, info.from_len),
            to: std_addr_from_c(info.to, info.to_len),
        }
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_recv(
    conn: &mut Connection, buf: *mut u8, buf_len: size_t, info: &RecvInfo,
) -> ssize_t {
    if buf_len > <ssize_t>::MAX as usize {
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
    from: sockaddr_storage,
    from_len: socklen_t,
    to: sockaddr_storage,
    to_len: socklen_t,

    at: timespec,
}

#[no_mangle]
pub extern "C" fn quiche_conn_send(
    conn: &mut Connection, out: *mut u8, out_len: size_t, out_info: &mut SendInfo,
) -> ssize_t {
    if out_len > <ssize_t>::MAX as usize {
        panic!("The provided buffer is too large");
    }

    let out = unsafe { slice::from_raw_parts_mut(out, out_len) };

    match conn.send(out) {
        Ok((v, info)) => {
            out_info.from_len = std_addr_to_c(&info.from, &mut out_info.from);
            out_info.to_len = std_addr_to_c(&info.to, &mut out_info.to);

            std_time_to_c(&info.at, &mut out_info.at);

            v as ssize_t
        },

        Err(e) => e.to_c(),
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_send_on_path(
    conn: &mut Connection, out: *mut u8, out_len: size_t, from: *const sockaddr,
    from_len: socklen_t, to: *const sockaddr, to_len: socklen_t,
    out_info: &mut SendInfo,
) -> ssize_t {
    if out_len > <ssize_t>::MAX as usize {
        panic!("The provided buffer is too large");
    }

    let from = optional_std_addr_from_c(from, from_len);
    let to = optional_std_addr_from_c(to, to_len);
    let out = unsafe { slice::from_raw_parts_mut(out, out_len) };

    match conn.send_on_path(out, from, to) {
        Ok((v, info)) => {
            out_info.from_len = std_addr_to_c(&info.from, &mut out_info.from);
            out_info.to_len = std_addr_to_c(&info.to, &mut out_info.to);

            std_time_to_c(&info.at, &mut out_info.at);

            v as ssize_t
        },

        Err(e) => e.to_c(),
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_stream_recv(
    conn: &mut Connection, stream_id: u64, out: *mut u8, out_len: size_t,
    fin: &mut bool, out_error_code: &mut u64,
) -> ssize_t {
    if out_len > <ssize_t>::MAX as usize {
        panic!("The provided buffer is too large");
    }

    let out = unsafe { slice::from_raw_parts_mut(out, out_len) };

    let (out_len, out_fin) = match conn.stream_recv(stream_id, out) {
        Ok(v) => v,

        Err(e) => {
            match e {
                Error::StreamReset(error) => *out_error_code = error,
                Error::StreamStopped(error) => *out_error_code = error,
                _ => {},
            }
            return e.to_c();
        },
    };

    *fin = out_fin;

    out_len as ssize_t
}

#[no_mangle]
pub extern "C" fn quiche_conn_stream_send(
    conn: &mut Connection, stream_id: u64, buf: *const u8, buf_len: size_t,
    fin: bool, out_error_code: &mut u64,
) -> ssize_t {
    if buf_len > <ssize_t>::MAX as usize {
        panic!("The provided buffer is too large");
    }

    let buf = if buf.is_null() {
        assert_eq!(buf_len, 0);
        &[]
    } else {
        unsafe { slice::from_raw_parts(buf, buf_len) }
    };

    match conn.stream_send(stream_id, buf, fin) {
        Ok(v) => v as ssize_t,

        Err(e) => {
            match e {
                Error::StreamReset(error) => *out_error_code = error,
                Error::StreamStopped(error) => *out_error_code = error,
                _ => {},
            }
            e.to_c()
        },
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_stream_priority(
    conn: &mut Connection, stream_id: u64, urgency: u8, incremental: bool,
) -> c_int {
    match conn.stream_priority(stream_id, urgency, incremental) {
        Ok(_) => 0,

        Err(e) => e.to_c() as c_int,
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_stream_shutdown(
    conn: &mut Connection, stream_id: u64, direction: Shutdown, err: u64,
) -> c_int {
    match conn.stream_shutdown(stream_id, direction, err) {
        Ok(_) => 0,

        Err(e) => e.to_c() as c_int,
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_stream_capacity(
    conn: &Connection, stream_id: u64,
) -> ssize_t {
    match conn.stream_capacity(stream_id) {
        Ok(v) => v as ssize_t,

        Err(e) => e.to_c(),
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_stream_readable(
    conn: &Connection, stream_id: u64,
) -> bool {
    conn.stream_readable(stream_id)
}

#[no_mangle]
pub extern "C" fn quiche_conn_stream_readable_next(conn: &mut Connection) -> i64 {
    conn.stream_readable_next().map(|v| v as i64).unwrap_or(-1)
}

#[no_mangle]
pub extern "C" fn quiche_conn_stream_writable(
    conn: &mut Connection, stream_id: u64, len: usize,
) -> c_int {
    match conn.stream_writable(stream_id, len) {
        Ok(true) => 1,

        Ok(false) => 0,

        Err(e) => e.to_c() as c_int,
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_stream_writable_next(conn: &mut Connection) -> i64 {
    conn.stream_writable_next().map(|v| v as i64).unwrap_or(-1)
}

#[no_mangle]
pub extern "C" fn quiche_conn_stream_finished(
    conn: &Connection, stream_id: u64,
) -> bool {
    conn.stream_finished(stream_id)
}

#[no_mangle]
pub extern "C" fn quiche_conn_readable(conn: &Connection) -> *mut StreamIter {
    Box::into_raw(Box::new(conn.readable()))
}

#[no_mangle]
pub extern "C" fn quiche_conn_writable(conn: &Connection) -> *mut StreamIter {
    Box::into_raw(Box::new(conn.writable()))
}

#[no_mangle]
pub extern "C" fn quiche_conn_max_send_udp_payload_size(
    conn: &Connection,
) -> usize {
    conn.max_send_udp_payload_size()
}

#[no_mangle]
pub extern "C" fn quiche_conn_is_readable(conn: &Connection) -> bool {
    conn.is_readable()
}

#[no_mangle]
pub extern "C" fn quiche_conn_close(
    conn: &mut Connection, app: bool, err: u64, reason: *const u8,
    reason_len: size_t,
) -> c_int {
    let reason = if reason.is_null() {
        assert_eq!(reason_len, 0);
        &[]
    } else {
        unsafe { slice::from_raw_parts(reason, reason_len) }
    };

    match conn.close(app, err, reason) {
        Ok(_) => 0,

        Err(e) => e.to_c() as c_int,
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_timeout_as_nanos(conn: &Connection) -> u64 {
    match conn.timeout() {
        Some(timeout) => timeout.as_nanos() as u64,

        None => u64::MAX,
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_timeout_as_millis(conn: &Connection) -> u64 {
    match conn.timeout() {
        Some(timeout) => timeout.as_millis() as u64,

        None => u64::MAX,
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_on_timeout(conn: &mut Connection) {
    conn.on_timeout()
}

#[no_mangle]
pub extern "C" fn quiche_conn_trace_id(
    conn: &Connection, out: &mut *const u8, out_len: &mut size_t,
) {
    let trace_id = conn.trace_id();

    *out = trace_id.as_ptr();
    *out_len = trace_id.len();
}

/// An iterator over connection ids.
#[derive(Default)]
pub struct ConnectionIdIter<'a> {
    cids: Vec<ConnectionId<'a>>,
    index: usize,
}

impl<'a> Iterator for ConnectionIdIter<'a> {
    type Item = ConnectionId<'a>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let v = self.cids.get(self.index)?;
        self.index += 1;
        Some(v.clone())
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_source_ids(
    conn: &Connection,
) -> *mut ConnectionIdIter<'_> {
    let vec = conn.source_ids().cloned().collect();
    Box::into_raw(Box::new(ConnectionIdIter {
        cids: vec,
        index: 0,
    }))
}

#[no_mangle]
pub extern "C" fn quiche_connection_id_iter_next(
    iter: &mut ConnectionIdIter, out: &mut *const u8, out_len: &mut size_t,
) -> bool {
    if let Some(conn_id) = iter.next() {
        let id = conn_id.as_ref();
        *out = id.as_ptr();
        *out_len = id.len();
        return true;
    }

    false
}

#[no_mangle]
pub extern "C" fn quiche_connection_id_iter_free(iter: *mut ConnectionIdIter) {
    drop(unsafe { Box::from_raw(iter) });
}

#[no_mangle]
pub extern "C" fn quiche_conn_source_id(
    conn: &Connection, out: &mut *const u8, out_len: &mut size_t,
) {
    let conn_id = conn.source_id();
    let id = conn_id.as_ref();
    *out = id.as_ptr();
    *out_len = id.len();
}

#[no_mangle]
pub extern "C" fn quiche_conn_destination_id(
    conn: &Connection, out: &mut *const u8, out_len: &mut size_t,
) {
    let conn_id = conn.destination_id();
    let id = conn_id.as_ref();

    *out = id.as_ptr();
    *out_len = id.len();
}

#[no_mangle]
pub extern "C" fn quiche_conn_application_proto(
    conn: &Connection, out: &mut *const u8, out_len: &mut size_t,
) {
    let proto = conn.application_proto();

    *out = proto.as_ptr();
    *out_len = proto.len();
}

#[no_mangle]
pub extern "C" fn quiche_conn_peer_cert(
    conn: &Connection, out: &mut *const u8, out_len: &mut size_t,
) {
    match conn.peer_cert() {
        Some(peer_cert) => {
            *out = peer_cert.as_ptr();
            *out_len = peer_cert.len();
        },

        None => *out_len = 0,
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_session(
    conn: &Connection, out: &mut *const u8, out_len: &mut size_t,
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
pub extern "C" fn quiche_conn_server_name(
    conn: &Connection, out: &mut *const u8, out_len: &mut size_t,
) {
    match conn.server_name() {
        Some(server_name) => {
            *out = server_name.as_ptr();
            *out_len = server_name.len();
        },

        None => *out_len = 0,
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_is_established(conn: &Connection) -> bool {
    conn.is_established()
}

#[no_mangle]
pub extern "C" fn quiche_conn_is_resumed(conn: &Connection) -> bool {
    conn.is_resumed()
}

#[no_mangle]
pub extern "C" fn quiche_conn_is_in_early_data(conn: &Connection) -> bool {
    conn.is_in_early_data()
}

#[no_mangle]
pub extern "C" fn quiche_conn_is_draining(conn: &Connection) -> bool {
    conn.is_draining()
}

#[no_mangle]
pub extern "C" fn quiche_conn_is_closed(conn: &Connection) -> bool {
    conn.is_closed()
}

#[no_mangle]
pub extern "C" fn quiche_conn_is_timed_out(conn: &Connection) -> bool {
    conn.is_timed_out()
}

#[no_mangle]
pub extern "C" fn quiche_conn_peer_error(
    conn: &Connection, is_app: *mut bool, error_code: *mut u64,
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
pub extern "C" fn quiche_conn_local_error(
    conn: &Connection, is_app: *mut bool, error_code: *mut u64,
    reason: &mut *const u8, reason_len: &mut size_t,
) -> bool {
    match &conn.local_error {
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
pub extern "C" fn quiche_stream_iter_next(
    iter: &mut StreamIter, stream_id: *mut u64,
) -> bool {
    if let Some(v) = iter.next() {
        unsafe { *stream_id = v };
        return true;
    }

    false
}

#[no_mangle]
pub extern "C" fn quiche_stream_iter_free(iter: *mut StreamIter) {
    drop(unsafe { Box::from_raw(iter) });
}

#[repr(C)]
pub struct Stats {
    recv: usize,
    sent: usize,
    lost: usize,
    retrans: usize,
    sent_bytes: u64,
    recv_bytes: u64,
    acked_bytes: u64,
    lost_bytes: u64,
    stream_retrans_bytes: u64,
    paths_count: usize,
    reset_stream_count_local: u64,
    stopped_stream_count_local: u64,
    reset_stream_count_remote: u64,
    stopped_stream_count_remote: u64,
}

pub struct TransportParams {
    max_idle_timeout: u64,
    max_udp_payload_size: u64,
    initial_max_data: u64,
    initial_max_stream_data_bidi_local: u64,
    initial_max_stream_data_bidi_remote: u64,
    initial_max_stream_data_uni: u64,
    initial_max_streams_bidi: u64,
    initial_max_streams_uni: u64,
    ack_delay_exponent: u64,
    max_ack_delay: u64,
    disable_active_migration: bool,
    active_conn_id_limit: u64,
    max_datagram_frame_size: ssize_t,
}

#[no_mangle]
pub extern "C" fn quiche_conn_stats(conn: &Connection, out: &mut Stats) {
    let stats = conn.stats();

    out.recv = stats.recv;
    out.sent = stats.sent;
    out.lost = stats.lost;
    out.retrans = stats.retrans;
    out.sent_bytes = stats.sent_bytes;
    out.recv_bytes = stats.recv_bytes;
    out.acked_bytes = stats.acked_bytes;
    out.lost_bytes = stats.lost_bytes;
    out.stream_retrans_bytes = stats.stream_retrans_bytes;
    out.paths_count = stats.paths_count;
    out.reset_stream_count_local = stats.reset_stream_count_local;
    out.stopped_stream_count_local = stats.stopped_stream_count_local;
    out.reset_stream_count_remote = stats.reset_stream_count_remote;
    out.stopped_stream_count_remote = stats.stopped_stream_count_remote;
}

#[no_mangle]
pub extern "C" fn quiche_conn_peer_transport_params(
    conn: &Connection, out: &mut TransportParams,
) -> bool {
    let tps = match conn.peer_transport_params() {
        Some(v) => v,
        None => return false,
    };

    out.max_idle_timeout = tps.max_idle_timeout;
    out.max_udp_payload_size = tps.max_udp_payload_size;
    out.initial_max_data = tps.initial_max_data;
    out.initial_max_stream_data_bidi_local =
        tps.initial_max_stream_data_bidi_local;
    out.initial_max_stream_data_bidi_remote =
        tps.initial_max_stream_data_bidi_remote;
    out.initial_max_stream_data_uni = tps.initial_max_stream_data_uni;
    out.initial_max_streams_bidi = tps.initial_max_streams_bidi;
    out.initial_max_streams_uni = tps.initial_max_streams_uni;
    out.ack_delay_exponent = tps.ack_delay_exponent;
    out.max_ack_delay = tps.max_ack_delay;
    out.disable_active_migration = tps.disable_active_migration;
    out.active_conn_id_limit = tps.active_conn_id_limit;
    out.max_datagram_frame_size = match tps.max_datagram_frame_size {
        None => Error::Done.to_c(),

        Some(v) => v as ssize_t,
    };

    true
}

#[repr(C)]
pub struct PathStats {
    local_addr: sockaddr_storage,
    local_addr_len: socklen_t,
    peer_addr: sockaddr_storage,
    peer_addr_len: socklen_t,
    validation_state: ssize_t,
    active: bool,
    recv: usize,
    sent: usize,
    lost: usize,
    retrans: usize,
    rtt: u64,
    min_rtt: u64,
    rttvar: u64,
    cwnd: usize,
    sent_bytes: u64,
    recv_bytes: u64,
    lost_bytes: u64,
    stream_retrans_bytes: u64,
    pmtu: usize,
    delivery_rate: u64,
}

#[no_mangle]
pub extern "C" fn quiche_conn_path_stats(
    conn: &Connection, idx: usize, out: &mut PathStats,
) -> c_int {
    let stats = match conn.path_stats().nth(idx) {
        Some(p) => p,
        None => return Error::Done.to_c() as c_int,
    };

    out.local_addr_len = std_addr_to_c(&stats.local_addr, &mut out.local_addr);
    out.peer_addr_len = std_addr_to_c(&stats.peer_addr, &mut out.peer_addr);
    out.validation_state = stats.validation_state.to_c();
    out.active = stats.active;
    out.recv = stats.recv;
    out.sent = stats.sent;
    out.lost = stats.lost;
    out.retrans = stats.retrans;
    out.rtt = stats.rtt.as_nanos() as u64;
    out.min_rtt = stats.min_rtt.unwrap_or_default().as_nanos() as u64;
    out.rttvar = stats.rttvar.as_nanos() as u64;
    out.cwnd = stats.cwnd;
    out.sent_bytes = stats.sent_bytes;
    out.recv_bytes = stats.recv_bytes;
    out.lost_bytes = stats.lost_bytes;
    out.stream_retrans_bytes = stats.stream_retrans_bytes;
    out.pmtu = stats.pmtu;
    out.delivery_rate = stats.delivery_rate;

    0
}

#[no_mangle]
pub extern "C" fn quiche_conn_is_server(conn: &Connection) -> bool {
    conn.is_server()
}

#[no_mangle]
pub extern "C" fn quiche_conn_dgram_max_writable_len(
    conn: &Connection,
) -> ssize_t {
    match conn.dgram_max_writable_len() {
        None => Error::Done.to_c(),

        Some(v) => v as ssize_t,
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_dgram_recv_front_len(conn: &Connection) -> ssize_t {
    match conn.dgram_recv_front_len() {
        None => Error::Done.to_c(),

        Some(v) => v as ssize_t,
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_dgram_recv_queue_len(conn: &Connection) -> ssize_t {
    conn.dgram_recv_queue_len() as ssize_t
}

#[no_mangle]
pub extern "C" fn quiche_conn_dgram_recv_queue_byte_size(
    conn: &Connection,
) -> ssize_t {
    conn.dgram_recv_queue_byte_size() as ssize_t
}

#[no_mangle]
pub extern "C" fn quiche_conn_dgram_send_queue_len(conn: &Connection) -> ssize_t {
    conn.dgram_send_queue_len() as ssize_t
}

#[no_mangle]
pub extern "C" fn quiche_conn_dgram_send_queue_byte_size(
    conn: &Connection,
) -> ssize_t {
    conn.dgram_send_queue_byte_size() as ssize_t
}

#[no_mangle]
pub extern "C" fn quiche_conn_dgram_send(
    conn: &mut Connection, buf: *const u8, buf_len: size_t,
) -> ssize_t {
    if buf_len > <ssize_t>::MAX as usize {
        panic!("The provided buffer is too large");
    }

    let buf = unsafe { slice::from_raw_parts(buf, buf_len) };

    match conn.dgram_send(buf) {
        Ok(_) => buf_len as ssize_t,

        Err(e) => e.to_c(),
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_dgram_recv(
    conn: &mut Connection, out: *mut u8, out_len: size_t,
) -> ssize_t {
    if out_len > <ssize_t>::MAX as usize {
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
pub extern "C" fn quiche_conn_dgram_purge_outgoing(
    conn: &mut Connection, f: extern "C" fn(*const u8, size_t) -> bool,
) {
    conn.dgram_purge_outgoing(|d: &[u8]| -> bool {
        let ptr: *const u8 = d.as_ptr();
        let len: size_t = d.len();

        f(ptr, len)
    });
}

#[no_mangle]
pub extern "C" fn quiche_conn_is_dgram_send_queue_full(
    conn: &Connection,
) -> bool {
    conn.is_dgram_send_queue_full()
}

#[no_mangle]
pub extern "C" fn quiche_conn_is_dgram_recv_queue_full(
    conn: &Connection,
) -> bool {
    conn.is_dgram_recv_queue_full()
}

#[no_mangle]
pub extern "C" fn quiche_conn_send_ack_eliciting(
    conn: &mut Connection,
) -> ssize_t {
    match conn.send_ack_eliciting() {
        Ok(()) => 0,
        Err(e) => e.to_c(),
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_send_ack_eliciting_on_path(
    conn: &mut Connection, local: &sockaddr, local_len: socklen_t,
    peer: &sockaddr, peer_len: socklen_t,
) -> ssize_t {
    let local = std_addr_from_c(local, local_len);
    let peer = std_addr_from_c(peer, peer_len);
    match conn.send_ack_eliciting_on_path(local, peer) {
        Ok(()) => 0,
        Err(e) => e.to_c(),
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_free(conn: *mut Connection) {
    drop(unsafe { Box::from_raw(conn) });
}

#[no_mangle]
pub extern "C" fn quiche_conn_peer_streams_left_bidi(conn: &Connection) -> u64 {
    conn.peer_streams_left_bidi()
}

#[no_mangle]
pub extern "C" fn quiche_conn_peer_streams_left_uni(conn: &Connection) -> u64 {
    conn.peer_streams_left_uni()
}

#[no_mangle]
pub extern "C" fn quiche_conn_send_quantum(conn: &Connection) -> size_t {
    conn.send_quantum() as size_t
}

#[no_mangle]
pub extern "C" fn quiche_conn_active_scids(conn: &Connection) -> size_t {
    conn.active_scids() as size_t
}

#[no_mangle]
pub extern "C" fn quiche_conn_scids_left(conn: &Connection) -> size_t {
    conn.scids_left() as size_t
}

#[no_mangle]
pub extern "C" fn quiche_conn_new_scid(
    conn: &mut Connection, scid: *const u8, scid_len: size_t,
    reset_token: *const u8, retire_if_needed: bool, scid_seq: *mut u64,
) -> c_int {
    let scid = unsafe { slice::from_raw_parts(scid, scid_len) };
    let scid = ConnectionId::from_ref(scid);

    let reset_token = unsafe { slice::from_raw_parts(reset_token, 16) };
    let reset_token = match reset_token.try_into() {
        Ok(rt) => rt,
        Err(_) => unreachable!(),
    };
    let reset_token = u128::from_be_bytes(reset_token);

    match conn.new_scid(&scid, reset_token, retire_if_needed) {
        Ok(c) => {
            unsafe { *scid_seq = c }
            0
        },
        Err(e) => e.to_c() as c_int,
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_retire_dcid(
    conn: &mut Connection, dcid_seq: u64,
) -> c_int {
    match conn.retire_dcid(dcid_seq) {
        Ok(_) => 0,
        Err(e) => e.to_c() as c_int,
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_available_dcids(conn: &Connection) -> size_t {
    conn.available_dcids() as size_t
}

#[no_mangle]
pub extern "C" fn quiche_conn_retired_scids(conn: &Connection) -> size_t {
    conn.retired_scids() as size_t
}

#[no_mangle]
pub extern "C" fn quiche_conn_retired_scid_next(
    conn: &mut Connection, out: &mut *const u8, out_len: &mut size_t,
) -> bool {
    match conn.retired_scid_next() {
        None => false,

        Some(conn_id) => {
            let id = conn_id.as_ref();
            *out = id.as_ptr();
            *out_len = id.len();
            true
        },
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_send_quantum_on_path(
    conn: &Connection, local: &sockaddr, local_len: socklen_t, peer: &sockaddr,
    peer_len: socklen_t,
) -> size_t {
    let local = std_addr_from_c(local, local_len);
    let peer = std_addr_from_c(peer, peer_len);

    conn.send_quantum_on_path(local, peer) as size_t
}

#[no_mangle]
pub extern "C" fn quiche_conn_paths_iter(
    conn: &Connection, from: &sockaddr, from_len: socklen_t,
) -> *mut SocketAddrIter {
    let addr = std_addr_from_c(from, from_len);

    Box::into_raw(Box::new(conn.paths_iter(addr)))
}

#[no_mangle]
pub extern "C" fn quiche_socket_addr_iter_next(
    iter: &mut SocketAddrIter, peer: &mut sockaddr_storage,
    peer_len: *mut socklen_t,
) -> bool {
    if let Some(v) = iter.next() {
        unsafe { *peer_len = std_addr_to_c(&v, peer) }
        return true;
    }

    false
}

#[no_mangle]
pub extern "C" fn quiche_socket_addr_iter_free(iter: *mut SocketAddrIter) {
    drop(unsafe { Box::from_raw(iter) });
}

#[no_mangle]
pub extern "C" fn quiche_conn_is_path_validated(
    conn: &Connection, from: &sockaddr, from_len: socklen_t, to: &sockaddr,
    to_len: socklen_t,
) -> c_int {
    let from = std_addr_from_c(from, from_len);
    let to = std_addr_from_c(to, to_len);
    match conn.is_path_validated(from, to) {
        Ok(v) => v as c_int,
        Err(e) => e.to_c() as c_int,
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_probe_path(
    conn: &mut Connection, local: &sockaddr, local_len: socklen_t,
    peer: &sockaddr, peer_len: socklen_t, seq: *mut u64,
) -> c_int {
    let local = std_addr_from_c(local, local_len);
    let peer = std_addr_from_c(peer, peer_len);
    match conn.probe_path(local, peer) {
        Ok(v) => {
            unsafe { *seq = v }
            0
        },
        Err(e) => e.to_c() as c_int,
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_migrate_source(
    conn: &mut Connection, local: &sockaddr, local_len: socklen_t, seq: *mut u64,
) -> c_int {
    let local = std_addr_from_c(local, local_len);
    match conn.migrate_source(local) {
        Ok(v) => {
            unsafe { *seq = v }
            0
        },
        Err(e) => e.to_c() as c_int,
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_migrate(
    conn: &mut Connection, local: &sockaddr, local_len: socklen_t,
    peer: &sockaddr, peer_len: socklen_t, seq: *mut u64,
) -> c_int {
    let local = std_addr_from_c(local, local_len);
    let peer = std_addr_from_c(peer, peer_len);
    match conn.migrate(local, peer) {
        Ok(v) => {
            unsafe { *seq = v }
            0
        },
        Err(e) => e.to_c() as c_int,
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_path_event_next(
    conn: &mut Connection,
) -> *mut PathEvent {
    match conn.path_event_next() {
        Some(v) => Box::into_raw(Box::new(v)),
        None => ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn quiche_path_event_type(ev: &PathEvent) -> u32 {
    match ev {
        PathEvent::New { .. } => 0,

        PathEvent::Validated { .. } => 1,

        PathEvent::FailedValidation { .. } => 2,

        PathEvent::Closed { .. } => 3,

        PathEvent::ReusedSourceConnectionId { .. } => 4,

        PathEvent::PeerMigrated { .. } => 5,
    }
}

#[no_mangle]
pub extern "C" fn quiche_path_event_new(
    ev: &PathEvent, local_addr: &mut sockaddr_storage,
    local_addr_len: &mut socklen_t, peer_addr: &mut sockaddr_storage,
    peer_addr_len: &mut socklen_t,
) {
    match ev {
        PathEvent::New(local, peer) => {
            *local_addr_len = std_addr_to_c(local, local_addr);
            *peer_addr_len = std_addr_to_c(peer, peer_addr)
        },

        _ => unreachable!(),
    }
}

#[no_mangle]
pub extern "C" fn quiche_path_event_validated(
    ev: &PathEvent, local_addr: &mut sockaddr_storage,
    local_addr_len: &mut socklen_t, peer_addr: &mut sockaddr_storage,
    peer_addr_len: &mut socklen_t,
) {
    match ev {
        PathEvent::Validated(local, peer) => {
            *local_addr_len = std_addr_to_c(local, local_addr);
            *peer_addr_len = std_addr_to_c(peer, peer_addr)
        },

        _ => unreachable!(),
    }
}

#[no_mangle]
pub extern "C" fn quiche_path_event_failed_validation(
    ev: &PathEvent, local_addr: &mut sockaddr_storage,
    local_addr_len: &mut socklen_t, peer_addr: &mut sockaddr_storage,
    peer_addr_len: &mut socklen_t,
) {
    match ev {
        PathEvent::FailedValidation(local, peer) => {
            *local_addr_len = std_addr_to_c(local, local_addr);
            *peer_addr_len = std_addr_to_c(peer, peer_addr)
        },

        _ => unreachable!(),
    }
}

#[no_mangle]
pub extern "C" fn quiche_path_event_closed(
    ev: &PathEvent, local_addr: &mut sockaddr_storage,
    local_addr_len: &mut socklen_t, peer_addr: &mut sockaddr_storage,
    peer_addr_len: &mut socklen_t,
) {
    match ev {
        PathEvent::Closed(local, peer) => {
            *local_addr_len = std_addr_to_c(local, local_addr);
            *peer_addr_len = std_addr_to_c(peer, peer_addr)
        },

        _ => unreachable!(),
    }
}

#[no_mangle]
pub extern "C" fn quiche_path_event_reused_source_connection_id(
    ev: &PathEvent, cid_sequence_number: &mut u64,
    old_local_addr: &mut sockaddr_storage, old_local_addr_len: &mut socklen_t,
    old_peer_addr: &mut sockaddr_storage, old_peer_addr_len: &mut socklen_t,
    local_addr: &mut sockaddr_storage, local_addr_len: &mut socklen_t,
    peer_addr: &mut sockaddr_storage, peer_addr_len: &mut socklen_t,
) {
    match ev {
        PathEvent::ReusedSourceConnectionId(id, old, new) => {
            *cid_sequence_number = *id;
            *old_local_addr_len = std_addr_to_c(&old.0, old_local_addr);
            *old_peer_addr_len = std_addr_to_c(&old.1, old_peer_addr);

            *local_addr_len = std_addr_to_c(&new.0, local_addr);
            *peer_addr_len = std_addr_to_c(&new.1, peer_addr)
        },

        _ => unreachable!(),
    }
}

#[no_mangle]
pub extern "C" fn quiche_path_event_peer_migrated(
    ev: &PathEvent, local_addr: &mut sockaddr_storage,
    local_addr_len: &mut socklen_t, peer_addr: &mut sockaddr_storage,
    peer_addr_len: &mut socklen_t,
) {
    match ev {
        PathEvent::PeerMigrated(local, peer) => {
            *local_addr_len = std_addr_to_c(local, local_addr);
            *peer_addr_len = std_addr_to_c(peer, peer_addr);
        },

        _ => unreachable!(),
    }
}

#[no_mangle]
pub extern "C" fn quiche_path_event_free(ev: *mut PathEvent) {
    drop(unsafe { Box::from_raw(ev) });
}

#[no_mangle]
pub extern "C" fn quiche_put_varint(
    buf: *mut u8, buf_len: size_t, val: u64,
) -> c_int {
    let buf = unsafe { slice::from_raw_parts_mut(buf, buf_len) };

    let mut b = octets::OctetsMut::with_slice(buf);
    match b.put_varint(val) {
        Ok(_) => 0,

        Err(e) => {
            let err: Error = e.into();
            err.to_c() as c_int
        },
    }
}

#[no_mangle]
pub extern "C" fn quiche_get_varint(
    buf: *const u8, buf_len: size_t, val: *mut u64,
) -> ssize_t {
    let buf = unsafe { slice::from_raw_parts(buf, buf_len) };

    let mut b = octets::Octets::with_slice(buf);
    match b.get_varint() {
        Ok(v) => unsafe { *val = v },

        Err(e) => {
            let err: Error = e.into();
            return err.to_c();
        },
    };

    b.off() as ssize_t
}

fn optional_std_addr_from_c(
    addr: *const sockaddr, addr_len: socklen_t,
) -> Option<SocketAddr> {
    if addr.is_null() || addr_len == 0 {
        return None;
    }

    Some({
        let addr = unsafe { slice::from_raw_parts(addr, addr_len as usize) };
        std_addr_from_c(addr.first().unwrap(), addr_len)
    })
}

fn std_addr_from_c(addr: &sockaddr, addr_len: socklen_t) -> SocketAddr {
    match addr.sa_family as _ {
        AF_INET => {
            assert!(addr_len as usize == size_of::<sockaddr_in>());

            let in4 = unsafe { *(addr as *const _ as *const sockaddr_in) };

            #[cfg(not(windows))]
            let ip_addr = Ipv4Addr::from(u32::from_be(in4.sin_addr.s_addr));
            #[cfg(windows)]
            let ip_addr = {
                let ip_bytes = unsafe { in4.sin_addr.S_un.S_un_b };

                Ipv4Addr::from([
                    ip_bytes.s_b1,
                    ip_bytes.s_b2,
                    ip_bytes.s_b3,
                    ip_bytes.s_b4,
                ])
            };

            let port = u16::from_be(in4.sin_port);

            let out = SocketAddrV4::new(ip_addr, port);

            out.into()
        },

        AF_INET6 => {
            assert!(addr_len as usize == size_of::<sockaddr_in6>());

            let in6 = unsafe { *(addr as *const _ as *const sockaddr_in6) };

            let ip_addr = Ipv6Addr::from(
                #[cfg(not(windows))]
                in6.sin6_addr.s6_addr,
                #[cfg(windows)]
                unsafe {
                    in6.sin6_addr.u.Byte
                },
            );

            let port = u16::from_be(in6.sin6_port);

            #[cfg(not(windows))]
            let scope_id = in6.sin6_scope_id;
            #[cfg(windows)]
            let scope_id = unsafe { in6.Anonymous.sin6_scope_id };

            let out =
                SocketAddrV6::new(ip_addr, port, in6.sin6_flowinfo, scope_id);

            out.into()
        },

        _ => unimplemented!("unsupported address type"),
    }
}

fn std_addr_to_c(addr: &SocketAddr, out: &mut sockaddr_storage) -> socklen_t {
    let sin_port = addr.port().to_be();

    match addr {
        SocketAddr::V4(addr) => unsafe {
            let sa_len = size_of::<sockaddr_in>();
            let out_in = out as *mut _ as *mut sockaddr_in;

            let s_addr = u32::from_ne_bytes(addr.ip().octets());

            #[cfg(not(windows))]
            let sin_addr = in_addr { s_addr };
            #[cfg(windows)]
            let sin_addr = in_addr {
                S_un: IN_ADDR_0 { S_addr: s_addr },
            };

            *out_in = sockaddr_in {
                sin_family: AF_INET as sa_family_t,

                sin_addr,

                #[cfg(any(
                    target_os = "macos",
                    target_os = "ios",
                    target_os = "watchos",
                    target_os = "freebsd",
                    target_os = "dragonfly",
                    target_os = "openbsd",
                    target_os = "netbsd"
                ))]
                sin_len: sa_len as u8,

                sin_port,

                sin_zero: std::mem::zeroed(),
            };

            sa_len as socklen_t
        },

        SocketAddr::V6(addr) => unsafe {
            let sa_len = size_of::<sockaddr_in6>();
            let out_in6 = out as *mut _ as *mut sockaddr_in6;

            #[cfg(not(windows))]
            let sin6_addr = in6_addr {
                s6_addr: addr.ip().octets(),
            };
            #[cfg(windows)]
            let sin6_addr = in6_addr {
                u: IN6_ADDR_0 {
                    Byte: addr.ip().octets(),
                },
            };

            *out_in6 = sockaddr_in6 {
                sin6_family: AF_INET6 as sa_family_t,

                sin6_addr,

                #[cfg(any(
                    target_os = "macos",
                    target_os = "ios",
                    target_os = "watchos",
                    target_os = "freebsd",
                    target_os = "dragonfly",
                    target_os = "openbsd",
                    target_os = "netbsd"
                ))]
                sin6_len: sa_len as u8,

                sin6_port: sin_port,

                sin6_flowinfo: addr.flowinfo(),

                #[cfg(not(windows))]
                sin6_scope_id: addr.scope_id(),
                #[cfg(windows)]
                Anonymous: SOCKADDR_IN6_0 {
                    sin6_scope_id: addr.scope_id(),
                },
            };

            sa_len as socklen_t
        },
    }
}

#[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "windows")))]
fn std_time_to_c(time: &Instant, out: &mut timespec) {
    const INSTANT_ZERO: Instant =
        unsafe { std::mem::transmute(std::time::UNIX_EPOCH) };

    let raw_time = time.duration_since(INSTANT_ZERO);

    out.tv_sec = raw_time.as_secs() as libc::time_t;
    out.tv_nsec = raw_time.subsec_nanos() as libc::c_long;
}

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "windows"))]
fn std_time_to_c(_time: &Instant, out: &mut timespec) {
    // TODO: implement Instant conversion for systems that don't use timespec.
    out.tv_sec = 0;
    out.tv_nsec = 0;
}

#[cfg(test)]
mod tests {
    use super::*;

    use libc::c_void;
    #[cfg(windows)]
    use windows_sys::Win32::Networking::WinSock::inet_ntop;

    #[test]
    fn addr_v4() {
        let addr = "127.0.0.1:8080".parse().unwrap();

        let mut out: sockaddr_storage = unsafe { std::mem::zeroed() };

        assert_eq!(
            std_addr_to_c(&addr, &mut out),
            size_of::<sockaddr_in>() as socklen_t
        );

        let s = ffi::CString::new("ddd.ddd.ddd.ddd").unwrap();

        let s = unsafe {
            let in_addr = &out as *const _ as *const sockaddr_in;
            assert_eq!(u16::from_be((*in_addr).sin_port), addr.port());

            let dst = s.into_raw();

            inet_ntop(
                AF_INET as _,
                &((*in_addr).sin_addr) as *const _ as *const c_void,
                dst as _,
                16,
            );

            ffi::CString::from_raw(dst).into_string().unwrap()
        };

        assert_eq!(s, "127.0.0.1");

        let addr = unsafe {
            std_addr_from_c(
                &*(&out as *const _ as *const sockaddr),
                size_of::<sockaddr_in>() as socklen_t,
            )
        };

        assert_eq!(addr, "127.0.0.1:8080".parse().unwrap());
    }

    #[test]
    fn addr_v6() {
        let addr = "[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:8080"
            .parse()
            .unwrap();

        let mut out: sockaddr_storage = unsafe { std::mem::zeroed() };

        assert_eq!(
            std_addr_to_c(&addr, &mut out),
            size_of::<sockaddr_in6>() as socklen_t
        );

        let s =
            ffi::CString::new("dddd:dddd:dddd:dddd:dddd:dddd:dddd:dddd").unwrap();

        let s = unsafe {
            let in6_addr = &out as *const _ as *const sockaddr_in6;
            assert_eq!(u16::from_be((*in6_addr).sin6_port), addr.port());

            let dst = s.into_raw();

            inet_ntop(
                AF_INET6 as _,
                &((*in6_addr).sin6_addr) as *const _ as *const c_void,
                dst as _,
                45,
            );

            ffi::CString::from_raw(dst).into_string().unwrap()
        };

        assert_eq!(s, "2001:db8:85a3::8a2e:370:7334");

        let addr = unsafe {
            std_addr_from_c(
                &*(&out as *const _ as *const sockaddr),
                size_of::<sockaddr_in6>() as socklen_t,
            )
        };

        assert_eq!(
            addr,
            "[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:8080"
                .parse()
                .unwrap()
        );
    }

    #[cfg(not(windows))]
    extern "C" {
        fn inet_ntop(
            af: c_int, src: *const c_void, dst: *mut c_char, size: socklen_t,
        ) -> *mut c_char;
    }
}
