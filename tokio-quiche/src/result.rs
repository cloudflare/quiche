// Copyright (C) 2025, Cloudflare, Inc.
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

use std::error::Error;
use std::io;

/// Generic thread-safe boxed error.
///
/// From all our prior experience we've learned that there is very little
/// practical use in concrete error types. On the surface it seems appealing to
/// use such errors, because they have, ahem, concrete type. But the flip side
/// is that code in big projects quickly ends up being polluted with endless
/// adapter error types to combine different APIs together, or, even worse, an
/// Error god-object gets introduced to accommodate all possible error types.
///
/// On rare occasions concrete error types can be used, where handling of the
/// error depends on the error kind. But, in practice, such cases are quite
/// rare.
pub type BoxError = Box<dyn Error + Send + Sync + 'static>;
/// [Result] alias based on [`BoxError`] for this crate.
pub type QuicResult<T> = Result<T, BoxError>;

/// Extension trait to add methods to [Result].
pub trait QuicResultExt<T, E> {
    /// Turns the [Result] into an [`io::Result`] with
    /// [`ErrorKind::Other`](io::ErrorKind::Other).
    fn into_io(self) -> io::Result<T>
    where
        E: Into<BoxError>;
}

impl<T, E> QuicResultExt<T, E> for Result<T, E> {
    #[inline]
    fn into_io(self) -> io::Result<T>
    where
        E: Into<BoxError>,
    {
        self.map_err(io::Error::other)
    }
}
