// Copyright (C) 2024, Cloudflare, Inc.
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

use plotters::style::RGBColor;
use plotters::style::BLACK;
use plotters::style::WHITE;

pub const FOREST_GREEN: RGBColor = RGBColor(15, 122, 27);
pub const PURPLE: RGBColor = RGBColor(54, 2, 89);
pub const TAUPE: RGBColor = RGBColor(133, 104, 3);
pub const MID_GREY: RGBColor = RGBColor(172, 172, 172);
pub const ORANGE: RGBColor = RGBColor(201, 93, 4);
pub const MUSTARD: RGBColor = RGBColor(158, 150, 2);
pub const SOFT_PINK: RGBColor = RGBColor(158, 82, 94);
pub const BROWN: RGBColor = RGBColor(74, 38, 2);
pub const BLUEY_BLACK: RGBColor = RGBColor(23, 32, 42);
pub const BLUEY_GREY: RGBColor = RGBColor(128, 139, 150);

/// Cycle through a set of colors
///
/// By default, the set is based on a modified version of the set from
/// https://stackoverflow.com/a/13781114
pub struct ColorCycle {
    pub colors: Vec<RGBColor>,
    pub initial_index: usize,
    pub tracking_index: usize,
}

impl ColorCycle {
    pub fn next_color(&mut self) -> RGBColor {
        let color = self.colors[self.tracking_index];
        if self.tracking_index == self.colors.len() - 1 {
            self.tracking_index = 0
        } else {
            self.tracking_index += 1
        }

        color
    }

    pub fn reset(&mut self) {
        self.tracking_index = self.initial_index;
    }
}

impl Default for ColorCycle {
    fn default() -> Self {
        let colors = vec![
            RGBColor(204, 81, 81),
            RGBColor(127, 51, 51),
            RGBColor(81, 204, 204),
            RGBColor(51, 127, 127),
            RGBColor(142, 204, 81),
            RGBColor(89, 127, 51),
            RGBColor(142, 81, 204),
            RGBColor(89, 51, 127),
            RGBColor(204, 173, 81),
            RGBColor(127, 108, 51),
            RGBColor(81, 204, 112),
            RGBColor(51, 127, 70),
            RGBColor(81, 112, 204),
            RGBColor(51, 70, 127),
            RGBColor(204, 81, 173),
            RGBColor(127, 51, 108),
            RGBColor(204, 127, 81),
            RGBColor(127, 79, 51),
            RGBColor(188, 204, 81),
            RGBColor(117, 127, 51),
            RGBColor(96, 204, 81),
            RGBColor(60, 127, 51),
            RGBColor(81, 204, 158),
            RGBColor(51, 127, 98),
            RGBColor(81, 158, 204),
            RGBColor(51, 98, 127),
            RGBColor(96, 81, 204),
            RGBColor(60, 51, 127),
            RGBColor(188, 81, 204),
            RGBColor(117, 51, 127),
            RGBColor(204, 81, 127),
            RGBColor(127, 51, 79),
            RGBColor(204, 104, 81),
            RGBColor(127, 65, 51),
            RGBColor(204, 150, 81),
            RGBColor(127, 94, 51),
            RGBColor(204, 196, 81),
            RGBColor(127, 122, 51),
            RGBColor(165, 204, 81),
            RGBColor(103, 127, 51),
            RGBColor(119, 204, 81),
            RGBColor(74, 127, 51),
            RGBColor(81, 204, 89),
            RGBColor(51, 127, 55),
            RGBColor(81, 204, 135),
            RGBColor(51, 127, 84),
            RGBColor(81, 204, 181),
            RGBColor(51, 127, 113),
            RGBColor(81, 181, 204),
            RGBColor(51, 113, 127),
            RGBColor(81, 135, 204),
            RGBColor(51, 84, 127),
            RGBColor(81, 89, 204),
            RGBColor(51, 55, 127),
            RGBColor(119, 81, 204),
            RGBColor(74, 51, 127),
            RGBColor(165, 81, 204),
            RGBColor(103, 51, 127),
            RGBColor(204, 81, 196),
            RGBColor(127, 51, 122),
            RGBColor(204, 81, 150),
            RGBColor(127, 51, 94),
            RGBColor(204, 81, 104),
            RGBColor(127, 51, 65),
            RGBColor(204, 93, 81),
            RGBColor(127, 58, 51),
            RGBColor(204, 116, 81),
            RGBColor(127, 72, 51),
            RGBColor(204, 138, 81),
            RGBColor(127, 86, 51),
            RGBColor(204, 161, 81),
            RGBColor(127, 101, 51),
            RGBColor(204, 184, 81),
            RGBColor(127, 115, 51),
            RGBColor(200, 204, 81),
            RGBColor(125, 127, 51),
            RGBColor(177, 204, 81),
            RGBColor(110, 127, 51),
            RGBColor(154, 204, 81),
            RGBColor(96, 127, 51),
            RGBColor(131, 204, 81),
            RGBColor(82, 127, 51),
            RGBColor(108, 204, 81),
            RGBColor(67, 127, 51),
            RGBColor(85, 204, 81),
            RGBColor(53, 127, 51),
            RGBColor(81, 204, 100),
            RGBColor(51, 127, 62),
            RGBColor(81, 204, 123),
            RGBColor(51, 127, 77),
            RGBColor(81, 204, 146),
            RGBColor(51, 127, 91),
            RGBColor(81, 204, 169),
            RGBColor(51, 127, 105),
            RGBColor(81, 204, 192),
            RGBColor(51, 127, 120),
            RGBColor(81, 192, 204),
            RGBColor(51, 120, 127),
            RGBColor(81, 169, 204),
            RGBColor(51, 105, 127),
        ];

        Self {
            colors,
            initial_index: 0,
            tracking_index: 0,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct PlotColors {
    pub fill: RGBColor,
    pub axis: RGBColor,
    pub bold_line: RGBColor,
    pub light_line: RGBColor,
    pub caption: RGBColor,
}

impl Default for PlotColors {
    fn default() -> Self {
        LIGHT_MODE
    }
}

pub const LIGHT_MODE: PlotColors = PlotColors {
    fill: WHITE,
    axis: BLUEY_GREY,
    bold_line: BLUEY_GREY,
    light_line: BLUEY_GREY,
    caption: BLACK,
};

pub const DARK_MODE: PlotColors = PlotColors {
    fill: BLUEY_BLACK,
    axis: BLUEY_GREY,
    bold_line: BLUEY_GREY,
    light_line: BLUEY_GREY,
    caption: WHITE,
};
