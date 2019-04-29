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

use std::ffi;
use std::ptr;
use std::slice;

use libc::c_char;
use libc::c_int;
use libc::c_void;
use libc::size_t;
use libc::ssize_t;

use crate::*;

#[no_mangle]
pub extern fn quiche_h3_config_new(
    num_placeholders: u64, max_header_list_size: u64,
    qpack_max_table_capacity: u64, qpack_blocked_streams: u64,
) -> *mut h3::Config {
    match h3::Config::new(
        num_placeholders,
        max_header_list_size,
        qpack_max_table_capacity,
        qpack_blocked_streams,
    ) {
        Ok(c) => Box::into_raw(Box::new(c)),

        Err(_) => ptr::null_mut(),
    }
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
pub extern fn quiche_h3_conn_poll(
    conn: &mut h3::Connection, quic_conn: &mut Connection,
    ev: *mut *const h3::Event,
) -> i64 {
    match conn.poll(quic_conn) {
        Ok((stream_id, v)) => {
            unsafe {
                *ev = Box::into_raw(Box::new(v));
            }

            stream_id as i64
        },

        Err(e) => e.to_c() as i64,
    }
}

#[no_mangle]
pub extern fn quiche_h3_event_type(ev: &h3::Event) -> u32 {
    match ev {
        h3::Event::Headers { .. } => 0,

        h3::Event::Data { .. } => 1,
    }
}

#[no_mangle]
pub extern fn quiche_h3_event_for_each_header(
    ev: &h3::Event,
    cb: fn(
        name: *const u8,
        name_len: size_t,
        value: *const u8,
        value_len: size_t,
        argp: *mut c_void,
    ),
    argp: *mut c_void,
) {
    match ev {
        h3::Event::Headers(headers) =>
            for h in headers {
                cb(
                    h.name().as_ptr(),
                    h.name().len(),
                    h.value().as_ptr(),
                    h.value().len(),
                    argp,
                );
            },

        h3::Event::Data { .. } => unreachable!(),
    }
}

#[no_mangle]
pub extern fn quiche_h3_event_data(
    ev: &h3::Event, out: *mut *const u8,
) -> size_t {
    match ev {
        h3::Event::Headers { .. } => unreachable!(),

        h3::Event::Data(data) => {
            unsafe {
                *out = (&data).as_ptr();
            }

            data.len()
        },
    }
}

#[no_mangle]
pub extern fn quiche_h3_event_free(ev: *mut h3::Event) {
    unsafe { Box::from_raw(ev) };
}

#[repr(C)]
pub struct Header {
    name: *mut c_char,
    value: *mut c_char,
}

#[no_mangle]
pub extern fn quiche_h3_send_request(
    conn: &mut h3::Connection, quic_conn: &mut Connection,
    headers: *const Header, headers_len: size_t, fin: bool,
) -> i64 {
    let headers = unsafe { slice::from_raw_parts(headers, headers_len) };

    let mut req_headers = Vec::new();

    for h in headers {
        req_headers.push(unsafe {
            let name = match ffi::CStr::from_ptr(h.name).to_str() {
                Ok(v) => v,

                Err(_) => return -1,
            };

            let value = match ffi::CStr::from_ptr(h.value).to_str() {
                Ok(v) => v,

                Err(_) => return -1,
            };

            h3::Header::new(name, value)
        });
    }

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
    let headers = unsafe { slice::from_raw_parts(headers, headers_len) };

    let mut resp_headers = Vec::new();

    for h in headers {
        resp_headers.push(unsafe {
            let name = match ffi::CStr::from_ptr(h.name).to_str() {
                Ok(v) => v,

                Err(_) => return -1,
            };

            let value = match ffi::CStr::from_ptr(h.value).to_str() {
                Ok(v) => v,

                Err(_) => return -1,
            };

            h3::Header::new(name, value)
        });
    }

    match conn.send_response(quic_conn, stream_id, &resp_headers, fin) {
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
pub extern fn quiche_h3_conn_free(conn: *mut h3::Connection) {
    unsafe { Box::from_raw(conn) };
}
