// Copyright (C) 2019, Cloudflare, Inc.
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

#[cfg(feature = "sfv")]
use std::convert::TryFrom;

use std::ptr;
use std::slice;

use libc::c_int;
use libc::c_void;
use libc::size_t;
use libc::ssize_t;

use crate::*;

use crate::h3::NameValue;
use crate::h3::Priority;

#[no_mangle]
pub extern fn quiche_h3_config_new() -> *mut h3::Config {
    match h3::Config::new() {
        Ok(c) => Box::into_raw(Box::new(c)),

        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub extern fn quiche_h3_config_set_max_field_section_size(
    config: &mut h3::Config, v: u64,
) {
    config.set_max_field_section_size(v);
}

#[no_mangle]
pub extern fn quiche_h3_config_set_qpack_max_table_capacity(
    config: &mut h3::Config, v: u64,
) {
    config.set_qpack_max_table_capacity(v);
}

#[no_mangle]
pub extern fn quiche_h3_config_set_qpack_blocked_streams(
    config: &mut h3::Config, v: u64,
) {
    config.set_qpack_blocked_streams(v);
}

#[no_mangle]
pub extern fn quiche_h3_config_enable_extended_connect(
    config: &mut h3::Config, enabled: bool,
) {
    config.enable_extended_connect(enabled);
}

#[no_mangle]
pub extern fn quiche_h3_config_free(config: *mut h3::Config) {
    unsafe { Box::from_raw(config) };
}

#[no_mangle]
pub extern fn quiche_h3_conn_new_with_transport(
    quic_conn: &mut Connection, config: &mut h3::Config,
) -> *mut h3::Connection {
    match h3::Connection::with_transport(quic_conn, config) {
        Ok(c) => Box::into_raw(Box::new(c)),

        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub extern fn quiche_h3_for_each_setting(
    conn: &h3::Connection,
    cb: extern fn(identifier: u64, value: u64, argp: *mut c_void) -> c_int,
    argp: *mut c_void,
) -> c_int {
    match conn.peer_settings_raw() {
        Some(raw) => {
            for setting in raw {
                let rc = cb(setting.0, setting.1, argp);

                if rc != 0 {
                    return rc;
                }
            }

            0
        },

        None => -1,
    }
}

#[no_mangle]
pub extern fn quiche_h3_conn_poll(
    conn: &mut h3::Connection, quic_conn: &mut Connection,
    ev: *mut *const h3::Event,
) -> i64 {
    match conn.poll(quic_conn) {
        Ok((id, v)) => {
            unsafe {
                *ev = Box::into_raw(Box::new(v));
            }

            id as i64
        },

        Err(e) => e.to_c() as i64,
    }
}

#[no_mangle]
pub extern fn quiche_h3_event_type(ev: &h3::Event) -> u32 {
    match ev {
        h3::Event::Headers { .. } => 0,

        h3::Event::Data { .. } => 1,

        h3::Event::Finished { .. } => 2,

        h3::Event::Datagram { .. } => 3,

        h3::Event::GoAway { .. } => 4,

        h3::Event::Reset { .. } => 5,

        h3::Event::PriorityUpdate { .. } => 6,
    }
}

#[no_mangle]
pub extern fn quiche_h3_event_for_each_header(
    ev: &h3::Event,
    cb: extern fn(
        name: *const u8,
        name_len: size_t,

        value: *const u8,
        value_len: size_t,

        argp: *mut c_void,
    ) -> c_int,
    argp: *mut c_void,
) -> c_int {
    match ev {
        h3::Event::Headers { list, .. } =>
            for h in list {
                let rc = cb(
                    h.name().as_ptr(),
                    h.name().len(),
                    h.value().as_ptr(),
                    h.value().len(),
                    argp,
                );

                if rc != 0 {
                    return rc;
                }
            },

        _ => unreachable!(),
    }

    0
}

#[no_mangle]
pub extern fn quiche_h3_event_headers_has_body(ev: &h3::Event) -> bool {
    match ev {
        h3::Event::Headers { has_body, .. } => *has_body,

        _ => unreachable!(),
    }
}

#[no_mangle]
pub extern fn quiche_h3_extended_connect_enabled_by_peer(
    conn: &h3::Connection,
) -> bool {
    conn.extended_connect_enabled_by_peer()
}

#[no_mangle]
pub extern fn quiche_h3_event_free(ev: *mut h3::Event) {
    unsafe { Box::from_raw(ev) };
}

#[repr(C)]
pub struct Header {
    name: *mut u8,
    name_len: usize,

    value: *mut u8,
    value_len: usize,
}

#[no_mangle]
pub extern fn quiche_h3_send_request(
    conn: &mut h3::Connection, quic_conn: &mut Connection,
    headers: *const Header, headers_len: size_t, fin: bool,
) -> i64 {
    let req_headers = headers_from_ptr(headers, headers_len);

    match conn.send_request(quic_conn, &req_headers, fin) {
        Ok(v) => v as i64,

        Err(e) => e.to_c() as i64,
    }
}

#[no_mangle]
pub extern fn quiche_h3_send_response(
    conn: &mut h3::Connection, quic_conn: &mut Connection, stream_id: u64,
    headers: *const Header, headers_len: size_t, fin: bool,
) -> c_int {
    let resp_headers = headers_from_ptr(headers, headers_len);

    match conn.send_response(quic_conn, stream_id, &resp_headers, fin) {
        Ok(_) => 0,

        Err(e) => e.to_c() as c_int,
    }
}

#[no_mangle]
pub extern fn quiche_h3_send_response_with_priority(
    conn: &mut h3::Connection, quic_conn: &mut Connection, stream_id: u64,
    headers: *const Header, headers_len: size_t, priority: &Priority, fin: bool,
) -> c_int {
    let resp_headers = headers_from_ptr(headers, headers_len);

    match conn.send_response_with_priority(
        quic_conn,
        stream_id,
        &resp_headers,
        priority,
        fin,
    ) {
        Ok(_) => 0,

        Err(e) => e.to_c() as c_int,
    }
}

#[no_mangle]
pub extern fn quiche_h3_send_body(
    conn: &mut h3::Connection, quic_conn: &mut Connection, stream_id: u64,
    body: *const u8, body_len: size_t, fin: bool,
) -> ssize_t {
    if body_len > <ssize_t>::max_value() as usize {
        panic!("The provided buffer is too large");
    }

    let body = unsafe { slice::from_raw_parts(body, body_len) };

    match conn.send_body(quic_conn, stream_id, body, fin) {
        Ok(v) => v as ssize_t,

        Err(e) => e.to_c(),
    }
}

#[no_mangle]
pub extern fn quiche_h3_recv_body(
    conn: &mut h3::Connection, quic_conn: &mut Connection, stream_id: u64,
    out: *mut u8, out_len: size_t,
) -> ssize_t {
    if out_len > <ssize_t>::max_value() as usize {
        panic!("The provided buffer is too large");
    }

    let out = unsafe { slice::from_raw_parts_mut(out, out_len) };

    match conn.recv_body(quic_conn, stream_id, out) {
        Ok(v) => v as ssize_t,

        Err(e) => e.to_c(),
    }
}

#[no_mangle]
#[cfg(feature = "sfv")]
pub extern fn quiche_h3_parse_extensible_priority(
    priority: *const u8, priority_len: size_t, parsed: &mut Priority,
) -> c_int {
    let priority = unsafe { slice::from_raw_parts(priority, priority_len) };

    match h3::Priority::try_from(priority) {
        Ok(v) => {
            parsed.urgency = v.urgency;
            parsed.incremental = v.incremental;
            0
        },

        Err(e) => e.to_c() as c_int,
    }
}

#[no_mangle]
pub extern fn quiche_h3_send_priority_update_for_request(
    conn: &mut h3::Connection, quic_conn: &mut Connection, stream_id: u64,
    priority: &Priority,
) -> c_int {
    match conn.send_priority_update_for_request(quic_conn, stream_id, priority) {
        Ok(()) => 0,

        Err(e) => e.to_c() as c_int,
    }
}

#[no_mangle]
pub extern fn quiche_h3_take_last_priority_update(
    conn: &mut h3::Connection, prioritized_element_id: u64,
    cb: extern fn(
        priority_field_value: *const u8,
        priority_field_value_len: size_t,
        argp: *mut c_void,
    ) -> c_int,
    argp: *mut c_void,
) -> c_int {
    match conn.take_last_priority_update(prioritized_element_id) {
        Ok(priority) => {
            let rc = cb(priority.as_ptr(), priority.len(), argp);

            if rc != 0 {
                return rc;
            }

            0
        },

        Err(e) => e.to_c() as c_int,
    }
}

#[no_mangle]
pub extern fn quiche_h3_dgram_enabled_by_peer(
    conn: &h3::Connection, quic_conn: &Connection,
) -> bool {
    conn.dgram_enabled_by_peer(quic_conn)
}

#[no_mangle]
pub extern fn quiche_h3_send_dgram(
    conn: &mut h3::Connection, quic_conn: &mut Connection, flow_id: u64,
    data: *const u8, data_len: size_t,
) -> c_int {
    if data_len > <ssize_t>::max_value() as usize {
        panic!("The provided buffer is too large");
    }

    let data = unsafe { slice::from_raw_parts(data, data_len) };

    match conn.send_dgram(quic_conn, flow_id, data) {
        Ok(_) => 0,

        Err(e) => e.to_c() as c_int,
    }
}

#[no_mangle]
pub extern fn quiche_h3_recv_dgram(
    conn: &mut h3::Connection, quic_conn: &mut Connection, flow_id: *mut u64,
    flow_id_len: *mut usize, out: *mut u8, out_len: size_t,
) -> ssize_t {
    if out_len > <ssize_t>::max_value() as usize {
        panic!("The provided buffer is too large");
    }

    let out = unsafe { slice::from_raw_parts_mut(out, out_len) };

    match conn.recv_dgram(quic_conn, out) {
        Ok((len, id, id_len)) => {
            unsafe { *flow_id = id };
            unsafe { *flow_id_len = id_len };
            len as ssize_t
        },

        Err(e) => e.to_c(),
    }
}

#[no_mangle]
pub extern fn quiche_h3_conn_free(conn: *mut h3::Connection) {
    unsafe { Box::from_raw(conn) };
}

fn headers_from_ptr<'a>(
    ptr: *const Header, len: size_t,
) -> Vec<h3::HeaderRef<'a>> {
    let headers = unsafe { slice::from_raw_parts(ptr, len) };

    let mut out = Vec::new();

    for h in headers {
        out.push({
            let name = unsafe { slice::from_raw_parts(h.name, h.name_len) };
            let value = unsafe { slice::from_raw_parts(h.value, h.value_len) };

            h3::HeaderRef::new(name, value)
        });
    }

    out
}
