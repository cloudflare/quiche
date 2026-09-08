// Copyright (C) 2026, Cloudflare, Inc.
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

use core::ffi::c_void;

/// FfiSlice exists to provide `as_ffi_ptr` on slices. Calling `as_ptr` on an
/// empty Rust slice may return the alignment of the type, rather than NULL, as
/// the pointer. When passing pointers into C/C++ code, that is not a valid
/// pointer. Thus this method should be used whenever passing a pointer to a
/// slice into C/BoringSSL code.
pub(crate) trait FfiSlice<T> {
    fn as_ffi_ptr(&self) -> *const T;

    fn as_ffi_void_ptr(&self) -> *const c_void {
        self.as_ffi_ptr() as *const c_void
    }
}

impl<T> FfiSlice<T> for [T] {
    fn as_ffi_ptr(&self) -> *const T {
        if self.is_empty() {
            core::ptr::null()
        } else {
            self.as_ptr()
        }
    }
}

impl<T, const N: usize> FfiSlice<T> for [T; N] {
    fn as_ffi_ptr(&self) -> *const T {
        if N == 0 {
            core::ptr::null()
        } else {
            self.as_ptr()
        }
    }
}

/// See [`FfiSlice`].
pub(crate) trait FfiMutSlice {
    fn as_mut_ffi_ptr(&mut self) -> *mut u8;
}

impl FfiMutSlice for [u8] {
    fn as_mut_ffi_ptr(&mut self) -> *mut u8 {
        if self.is_empty() {
            core::ptr::null_mut()
        } else {
            self.as_mut_ptr()
        }
    }
}

impl<const N: usize> FfiMutSlice for [u8; N] {
    fn as_mut_ffi_ptr(&mut self) -> *mut u8 {
        if N == 0 {
            core::ptr::null_mut()
        } else {
            self.as_mut_ptr()
        }
    }
}
