// Copyright (C) 2018-2025, Cloudflare, Inc.
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

#[cfg(not(feature = "rustls"))]
mod boringssl_openssl;
#[cfg(not(feature = "rustls"))]
pub use boringssl_openssl::*;

#[cfg(feature = "rustls")]
mod rustls;
#[cfg(feature = "rustls")]
pub use rustls::*;

use crate::packet;
use crate::ConnectionError;

pub struct ExData<'a> {
    #[cfg(not(feature = "rustls"))]
    pub application_protos: &'a Vec<Vec<u8>>,

    pub crypto_ctx: &'a mut [packet::CryptoContext; packet::Epoch::count()],

    pub session: &'a mut Option<Vec<u8>>,

    pub local_error: &'a mut Option<ConnectionError>,

    #[cfg(not(feature = "rustls"))]
    pub keylog: Option<&'a mut Box<dyn std::io::Write + Send + Sync>>,

    #[cfg(not(feature = "rustls"))]
    pub trace_id: &'a str,

    pub recovery_config: crate::recovery::RecoveryConfig,

    pub tx_cap_factor: f64,

    #[cfg(not(feature = "rustls"))]
    pub is_server: bool,
}
