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

#[derive(Clone, Copy)]
pub struct XMinMax {
    pub min: f64,
    pub max: f64,
}

impl XMinMax {
    pub fn new(min: f64, max: f64, start: Option<f64>, end: Option<f64>) -> Self {
        let mut minmax = Self { min, max };

        if let Some(s) = start {
            minmax.min = s;
        }

        if let Some(e) = end {
            minmax.max = minmax.max.min(e);
        }

        minmax
    }

    pub fn range(&self) -> std::ops::Range<f64> {
        self.min..self.max
    }
}

pub struct XYMinMax<Y> {
    pub x: XMinMax,
    pub y_range: std::ops::Range<Y>,
}

impl<Y> XYMinMax<Y> {
    pub fn init(
        x_data_range: std::ops::Range<f64>, x_start: Option<f64>,
        x_end: Option<f64>, y_range: std::ops::Range<Y>,
    ) -> Self {
        let x =
            XMinMax::new(x_data_range.start, x_data_range.end, x_start, x_end);

        Self { x, y_range }
    }
}
