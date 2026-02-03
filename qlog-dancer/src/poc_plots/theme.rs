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

//! Theme support for plots - thin wrapper around PlotConfig for plotters.
//!
//! All configuration comes from PlotConfig (which loads from config.toml).
//! This module only provides convenience methods for plotters integration.

use plotters::prelude::SeriesLabelPosition;
use plotters::style::RGBColor;
use plotters::style::ShapeStyle;
use plotters::style::BLACK;
use plotters::style::WHITE;

use super::config::PlotConfig;

/// Parse legend position string to plotters SeriesLabelPosition.
/// Supports matplotlib-style position names.
pub fn parse_legend_position(pos: &str) -> SeriesLabelPosition {
    match pos.to_lowercase().replace('_', " ").as_str() {
        "upper right" => SeriesLabelPosition::UpperRight,
        "upper left" => SeriesLabelPosition::UpperLeft,
        "lower right" => SeriesLabelPosition::LowerRight,
        "lower left" => SeriesLabelPosition::LowerLeft,
        "upper middle" => SeriesLabelPosition::UpperMiddle,
        "lower middle" => SeriesLabelPosition::LowerMiddle,
        "middle right" => SeriesLabelPosition::MiddleRight,
        "middle left" => SeriesLabelPosition::MiddleLeft,
        _ => SeriesLabelPosition::UpperLeft,
    }
}

/// A color cycle that wraps around when exhausted.
/// Colors come from PlotConfig palettes.
#[derive(Debug, Clone)]
pub struct ColorCycle {
    colors: Vec<RGBColor>,
    index: usize,
}

impl ColorCycle {
    /// Create a new color cycle from a config's active palette.
    pub fn from_config(config: &PlotConfig) -> Self {
        let colors = config
            .active_palette()
            .iter()
            .map(|rgb| RGBColor(rgb[0], rgb[1], rgb[2]))
            .collect();

        Self { colors, index: 0 }
    }

    /// Get the next color in the cycle.
    pub fn next(&mut self) -> RGBColor {
        let color = self.colors[self.index];
        self.index = (self.index + 1) % self.colors.len();
        color
    }

    /// Peek at the next color without advancing.
    pub fn peek(&self) -> RGBColor {
        self.colors[self.index]
    }

    /// Reset the cycle to the beginning.
    pub fn reset(&mut self) {
        self.index = 0;
    }

    /// Get a color by index (wraps around).
    pub fn get(&self, index: usize) -> RGBColor {
        self.colors[index % self.colors.len()]
    }
}

/// Theme derived from PlotConfig for use with plotters.
/// All values come from PlotConfig - no hardcoded defaults here.
#[derive(Debug, Clone)]
pub struct PlotTheme {
    pub fill: RGBColor,
    pub axis: RGBColor,
    pub bold_line: RGBColor,
    pub light_line: RGBColor,
    pub caption: RGBColor,
    pub line_width: u32,
    pub line_alpha: f64,
    pub grid_line_width: u32,
    pub grid_alpha: f64,
    pub title_fontsize: f32,
    pub label_fontsize: f32,
    pub display_title: bool,
    pub display_legend: bool,
    pub color_cycle: ColorCycle,
}

impl PlotTheme {
    /// Create a theme from a PlotConfig.
    /// All values come from config.toml - no hardcoded fallbacks.
    pub fn from_config(config: &PlotConfig) -> Self {
        let fill = parse_color(&config.figure.facecolor).unwrap_or(WHITE);
        let caption = if fill == WHITE { BLACK } else { WHITE };

        // Use colors from config for fallbacks
        let bold_line_fallback = parse_color(&config.colors.bold_line).unwrap_or(WHITE);
        let light_line_fallback = parse_color(&config.colors.light_line).unwrap_or(WHITE);

        Self {
            fill,
            axis: parse_color(&config.axes.edgecolor).unwrap_or(BLACK),
            bold_line: parse_color(&config.xticks.major.color)
                .unwrap_or(bold_line_fallback),
            light_line: parse_color(&config.xticks.minor.color)
                .unwrap_or(light_line_fallback),
            caption,
            line_width: config.lines.linewidth as u32,
            line_alpha: config.lines.alpha as f64,
            grid_line_width: config.grid.linewidth as u32,
            grid_alpha: config.grid.alpha as f64,
            title_fontsize: config.title.fontsize,
            label_fontsize: config.font.size,
            display_title: config.title.display,
            display_legend: config.legend.frameon,
            color_cycle: ColorCycle::from_config(config),
        }
    }

    /// Get a ShapeStyle for a line with the given color.
    pub fn line_style(&self, color: RGBColor) -> ShapeStyle {
        ShapeStyle::from(color).stroke_width(self.line_width)
    }
}

impl Default for PlotTheme {
    fn default() -> Self {
        // Default theme comes from default PlotConfig
        Self::from_config(&PlotConfig::default())
    }
}

/// Parse a color string to RGBColor.
/// Supports: "white", "black", "lightgrey", or hex "#RRGGBB".
pub fn parse_color(s: &str) -> Option<RGBColor> {
    match s.to_lowercase().as_str() {
        "white" => Some(WHITE),
        "black" => Some(BLACK),
        "lightgrey" | "lightgray" => Some(RGBColor(211, 211, 211)),
        "grey" | "gray" => Some(RGBColor(128, 128, 128)),
        s if s.starts_with('#') && s.len() == 7 => {
            let r = u8::from_str_radix(&s[1..3], 16).ok()?;
            let g = u8::from_str_radix(&s[3..5], 16).ok()?;
            let b = u8::from_str_radix(&s[5..7], 16).ok()?;
            Some(RGBColor(r, g, b))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_color_cycle_from_config() {
        let config = PlotConfig::default();
        let mut cycle = ColorCycle::from_config(&config);

        // Default is qvis palette, first color is forest_green
        let c0 = cycle.next();
        assert_eq!(c0, RGBColor(15, 122, 27));

        cycle.reset();
        assert_eq!(cycle.next(), c0);
    }

    #[test]
    fn test_parse_color() {
        assert_eq!(parse_color("white"), Some(WHITE));
        assert_eq!(parse_color("BLACK"), Some(BLACK));
        assert_eq!(parse_color("#FF0000"), Some(RGBColor(255, 0, 0)));
        assert_eq!(parse_color("invalid"), None);
    }

    #[test]
    fn test_theme_from_config() {
        let config = PlotConfig::default();
        let theme = PlotTheme::from_config(&config);

        // Values should match config defaults
        assert_eq!(theme.line_width, config.lines.linewidth as u32);
        assert_eq!(theme.display_title, config.title.display);
    }

    #[test]
    fn test_matplotlib_palette() {
        let mut config = PlotConfig::default();
        config.lines.palette = "matplotlib".to_string();

        let mut cycle = ColorCycle::from_config(&config);
        // matplotlib C0 blue
        assert_eq!(cycle.next(), RGBColor(31, 119, 180));
    }
}
