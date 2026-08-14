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

use super::*;

use crate::ffi_slice::FfiSlice;

use bssl_sys::sk_num;
use bssl_sys::sk_value;
use bssl_sys::CRYPTO_BUFFER_data;
use bssl_sys::CRYPTO_BUFFER_len;
use bssl_sys::OPENSSL_free;
use bssl_sys::SSL_CTX_set_early_data_enabled;
use bssl_sys::SSL_SESSION_free;
use bssl_sys::SSL_SESSION_from_bytes;
use bssl_sys::SSL_SESSION_to_bytes;
use bssl_sys::SSL_get0_peer_certificates;
use bssl_sys::SSL_get_SSL_CTX;
use bssl_sys::SSL_get_curve_id;
use bssl_sys::SSL_get_curve_name;
use bssl_sys::SSL_get_early_data_reason;
use bssl_sys::SSL_get_peer_signature_algorithm;
use bssl_sys::SSL_get_signature_algorithm_name;
use bssl_sys::SSL_in_early_data;
use bssl_sys::SSL_reset_early_data_reject;
use bssl_sys::SSL_set_quic_early_data_context;
use bssl_sys::SSL_set_session;
use bssl_sys::CRYPTO_BUFFER;

pub use bssl_sys::SSL_QUIC_METHOD;

#[cfg(test)]
use bssl_sys::SSL_set_private_key_method;
#[cfg(test)]
use bssl_sys::SSL_PRIVATE_KEY_METHOD;

pub(super) static QUICHE_STREAM_METHOD: SSL_QUIC_METHOD = SSL_QUIC_METHOD {
    set_read_secret: Some(bssl_set_read_secret),
    set_write_secret: Some(bssl_set_write_secret),
    add_handshake_data: Some(bssl_add_handshake_data),
    flush_flight: Some(bssl_flush_flight),
    send_alert: Some(bssl_send_alert),
};

impl Context {
    pub fn set_early_data_enabled(&mut self, enabled: bool) {
        // SAFETY: FFI call, but there are no safety preconditions.
        unsafe {
            SSL_CTX_set_early_data_enabled(self.as_mut_ptr(), i32::from(enabled));
        }
    }
}

impl Handshake {
    pub fn set_quic_early_data_context(&mut self, context: &[u8]) -> Result<()> {
        // SAFETY: FFI call, but there are no safety preconditions.
        map_result(unsafe {
            SSL_set_quic_early_data_context(
                self.as_mut_ptr(),
                context.as_ffi_ptr(),
                context.len(),
            )
        })
    }

    pub fn set_session(&mut self, session: &[u8]) -> Result<()> {
        // SAFETY: FFI call, but there are no safety preconditions.
        let ctx = unsafe { SSL_get_SSL_CTX(self.as_ptr()) };

        if ctx.is_null() {
            return Err(Error::TlsFail);
        }

        // SAFETY: FFI call, but there are no safety preconditions.
        let session = unsafe {
            SSL_SESSION_from_bytes(session.as_ffi_ptr(), session.len(), ctx)
        };

        if session.is_null() {
            return Err(Error::TlsFail);
        }

        // SAFETY: FFI call, but there are no safety preconditions.
        let rc = unsafe { SSL_set_session(self.as_mut_ptr(), session) };

        // SAFETY: FFI call, but there are no safety preconditions.
        unsafe {
            SSL_SESSION_free(session);
        }

        map_result(rc)
    }

    pub fn reset_early_data_reject(&mut self) {
        // SAFETY: FFI call, but there are no safety preconditions.
        unsafe { SSL_reset_early_data_reject(self.as_mut_ptr()) };
    }

    pub fn curve(&self) -> Option<String> {
        // SAFETY: FFI call, but there are no safety preconditions.
        let curve_id = unsafe { SSL_get_curve_id(self.as_ptr()) };
        if curve_id == 0 {
            return None;
        }

        // SAFETY: FFI call, but there are no safety preconditions.
        let curve_name = unsafe { SSL_get_curve_name(curve_id) };
        if curve_name.is_null() {
            return None;
        }

        // SAFETY: FFI call, but there are no safety preconditions.
        let curve = match unsafe { ffi::CStr::from_ptr(curve_name).to_str() } {
            Ok(v) => v,

            Err(_) => return None,
        };

        Some(curve.to_string())
    }

    pub fn sigalg(&self) -> Option<String> {
        // SAFETY: FFI call, but there are no safety preconditions.
        let sigalg_id =
            unsafe { SSL_get_peer_signature_algorithm(self.as_ptr()) };
        if sigalg_id == 0 {
            return None;
        }

        // SAFETY: FFI call, but there are no safety preconditions.
        let sigalg_name =
            unsafe { SSL_get_signature_algorithm_name(sigalg_id, 1) };
        if sigalg_name.is_null() {
            return None;
        }

        // SAFETY: FFI call, but there are no safety preconditions.
        let sigalg = match unsafe { ffi::CStr::from_ptr(sigalg_name).to_str() } {
            Ok(v) => v,

            Err(_) => return None,
        };

        Some(sigalg.to_string())
    }

    pub fn peer_cert_chain(&self) -> Option<Vec<Vec<u8>>> {
        // SAFETY: FFI call, but there are no safety preconditions.
        let chain = unsafe {
            map_result_ptr(SSL_get0_peer_certificates(self.as_ptr())).ok()?
        };

        // SAFETY: FFI call, but there are no safety preconditions.
        let num = unsafe { sk_num(chain as *const _ as *const _) };
        if num == 0 {
            return None;
        }

        let mut cert_chain = vec![];
        for i in 0..num {
            // SAFETY: FFI call, but there are no safety preconditions.
            let buffer = map_result_ptr(unsafe {
                sk_value(chain as *const _ as *const _, i) as *const CRYPTO_BUFFER
            })
            .ok()?;

            // SAFETY: FFI call, but there are no safety preconditions.
            let out_len = unsafe { CRYPTO_BUFFER_len(buffer) };
            if out_len == 0 {
                return None;
            }

            let out = unsafe { CRYPTO_BUFFER_data(buffer) };
            // SAFETY: FFI call, but there are no safety preconditions.
            let slice = unsafe { slice::from_raw_parts(out, out_len) };

            cert_chain.push(slice.to_vec());
        }

        Some(cert_chain)
    }

    pub fn peer_cert(&self) -> Option<Vec<u8>> {
        // SAFETY: FFI call, but there are no safety preconditions.
        let chain = unsafe {
            map_result_ptr(SSL_get0_peer_certificates(self.as_ptr())).ok()?
        };
        if unsafe { sk_num(chain as *const _ as *const _) == 0 } {
            return None;
        }

        // SAFETY: FFI call, but there are no safety preconditions.
        let buffer = unsafe {
            map_result_ptr(sk_value(chain as *const _ as *const _, 0)
                as *const CRYPTO_BUFFER)
            .ok()?
        };

        // SAFETY: FFI call, but there are no safety preconditions.
        let out_len = unsafe { CRYPTO_BUFFER_len(buffer) };
        if out_len == 0 {
            return None;
        }

        // SAFETY: FFI call, but there are no safety preconditions.
        let out = unsafe { CRYPTO_BUFFER_data(buffer) };
        let peer_cert = unsafe { slice::from_raw_parts(out, out_len).to_vec() };

        Some(peer_cert)
    }

    // Only used for testing handling of failure during key signing.
    #[cfg(test)]
    pub fn set_failing_private_key_method(&mut self) {
        // SAFETY: FFI call, but there are no safety preconditions.
        unsafe extern "C" fn failing_sign(
            _ssl: *mut SSL, _out: *mut u8, _out_len: *mut usize, _max_out: usize,
            _signature_algorithm: u16, _in: *const u8, _in_len: usize,
        ) -> ssl_private_key_result_t {
            bssl_sys::ssl_private_key_result_t_ssl_private_key_failure
        }

        // SAFETY: FFI call, but there are no safety preconditions.
        unsafe extern "C" fn failing_decrypt(
            _ssl: *mut SSL, _out: *mut u8, _out_len: *mut usize, _max_out: usize,
            _in: *const u8, _in_len: usize,
        ) -> ssl_private_key_result_t {
            bssl_sys::ssl_private_key_result_t_ssl_private_key_failure
        }

        // SAFETY: FFI call, but there are no safety preconditions.
        unsafe extern "C" fn failing_complete(
            _ssl: *mut SSL, _out: *mut u8, _out_len: *mut usize, _max_out: usize,
        ) -> ssl_private_key_result_t {
            bssl_sys::ssl_private_key_result_t_ssl_private_key_failure
        }

        static QUICHE_PRIVATE_KEY_METHOD: SSL_PRIVATE_KEY_METHOD =
            SSL_PRIVATE_KEY_METHOD {
                decrypt: Some(failing_decrypt),
                sign: Some(failing_sign),
                complete: Some(failing_complete),
            };

        // SAFETY: FFI call, but there are no safety preconditions.
        unsafe {
            SSL_set_private_key_method(
                self.as_mut_ptr(),
                &QUICHE_PRIVATE_KEY_METHOD as *const SSL_PRIVATE_KEY_METHOD,
            );
        }
    }

    pub fn is_in_early_data(&self) -> bool {
        // SAFETY: FFI call, preconditions:
        // - self is a valid SSL.
        unsafe { SSL_in_early_data(self.as_ptr()) == 1 }
    }

    pub fn early_data_reason(&self) -> u32 {
        // SAFETY: FFI call, but there are no safety preconditions.
        let reuse_reason_status =
            unsafe { SSL_get_early_data_reason(self.as_ptr()) };
        reuse_reason_status as u32
    }
}

pub(super) fn get_session_bytes(session: *mut SSL_SESSION) -> Result<Vec<u8>> {
    let mut out: *mut u8 = ptr::null_mut();
    let mut out_len: usize = 0;

    // SAFETY: FFI call, but there are no safety preconditions.
    if unsafe { SSL_SESSION_to_bytes(session as *mut _, &mut out, &mut out_len) }
        == 0
    {
        return Err(Error::TlsFail);
    }

    // SAFETY: FFI call, but there are no safety preconditions.
    let session_bytes = unsafe { slice::from_raw_parts(out, out_len).to_vec() };
    unsafe { OPENSSL_free(out as *mut c_void) };

    Ok(session_bytes)
}

pub(super) const TLS_ERROR: c_int = 3;
