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

//! TOML-based configuration with matplotlib-style options.
//!
//! This module provides a configuration system inspired by matplotlib's rcParams,
//! allowing users to customize plot appearance through a config.toml file.
//!
//! The default configuration is embedded from config.toml - all styling changes
//! can be made by editing that file without recompilation.

use plotters::style::RGBColor;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

/// Embedded default configuration from config.toml.
/// This is the single source of truth for all default values.
const DEFAULT_CONFIG_TOML: &str = include_str!("config.toml");

/// Root configuration structure matching the TOML schema from FLPROTO-5244.
/// 
/// Use `PlotConfig::default()` to get the embedded config.toml values.
/// Use `PlotConfig::from_file()` to load a custom config (missing fields use defaults).
#[derive(Debug, Clone, Deserialize)]
pub struct PlotConfig {
    #[serde(default)]
    pub colors: ColorsConfig,
    #[serde(default)]
    pub palettes: PalettesConfig,
    #[serde(default)]
    pub lines: LinesConfig,
    #[serde(default)]
    pub axes: AxesConfig,
    #[serde(default)]
    pub xticks: TicksConfig,
    #[serde(default)]
    pub yticks: TicksConfig,
    #[serde(default)]
    pub xlabel: LabelConfig,
    #[serde(default)]
    pub ylabel: LabelConfig,
    #[serde(default)]
    pub grid: GridConfig,
    #[serde(default)]
    pub legend: LegendConfig,
    #[serde(default)]
    pub title: TitleConfig,
    #[serde(default)]
    pub font: FontConfig,
    #[serde(default)]
    pub figure: FigureConfig,
    #[serde(default)]
    pub output: OutputConfig,
}

impl Default for PlotConfig {
    fn default() -> Self {
        // Parse from embedded TOML - this is the single source of truth
        Self::from_str(DEFAULT_CONFIG_TOML)
            .expect("Embedded config.toml must be valid")
    }
}

impl PlotConfig {
    /// Load configuration from a TOML file.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path.as_ref())
            .map_err(|e| ConfigError::IoError(e.to_string()))?;
        Self::from_str(&content)
    }

    /// Parse configuration from a TOML string.
    pub fn from_str(toml_str: &str) -> Result<Self, ConfigError> {
        toml::from_str(toml_str).map_err(|e| ConfigError::ParseError(e.to_string()))
    }

    /// Get the active palette based on lines.palette setting.
    /// Supports any palette defined in config.toml under [palettes.NAME].
    pub fn active_palette(&self) -> &[[u8; 3]] {
        self.palettes.palettes
            .get(&self.lines.palette)
            .map(|p| p.colors.as_slice())
            .unwrap_or_else(|| {
                // Fallback to qvis if specified palette not found
                self.palettes.palettes
                    .get("qvis")
                    .map(|p| p.colors.as_slice())
                    .unwrap_or(&[])
            })
    }

    /// Get a color from the active palette by index (wraps around).
    pub fn palette_color(&self, index: usize) -> RGBColor {
        let palette = self.active_palette();
        let rgb = palette[index % palette.len()];
        RGBColor(rgb[0], rgb[1], rgb[2])
    }
}

#[derive(Debug, Clone)]
pub enum ConfigError {
    IoError(String),
    ParseError(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::IoError(e) => write!(f, "IO error: {}", e),
            ConfigError::ParseError(e) => write!(f, "Parse error: {}", e),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Fallback colors configuration.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct ColorsConfig {
    #[serde(default)]
    pub bold_line: String,
    #[serde(default)]
    pub light_line: String,
}

/// Color palettes configuration.
/// Uses HashMap to support any custom palette defined in config.toml.
/// Example: [palettes.custom] with colors = [[255, 0, 0], ...]
#[derive(Debug, Clone, Deserialize, Default)]
pub struct PalettesConfig {
    #[serde(flatten)]
    pub palettes: HashMap<String, Palette>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Palette {
    #[serde(default)]
    pub colors: Vec<[u8; 3]>,
}

/// Line styling configuration.
/// All values come from config.toml.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct LinesConfig {
    #[serde(default)]
    pub linewidth: f32,
    #[serde(default)]
    pub style: String,
    #[serde(default)]
    pub alpha: f32,
    #[serde(default)]
    pub palette: String,
    #[serde(default)]
    pub markers: MarkersConfig,
    #[serde(default)]
    pub line_style: LineStyleConfig,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct MarkersConfig {
    #[serde(default)]
    pub style: String,
    #[serde(default)]
    pub size: f32,
    #[serde(default)]
    pub edgewidth: f32,
    #[serde(default)]
    pub facecolor: String,
    #[serde(default)]
    pub edgecolor: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct LineStyleConfig {
    #[serde(default)]
    pub antialiased: bool,
    #[serde(default)]
    pub dash_joinstyle: String,
    #[serde(default)]
    pub dash_capstyle: String,
    #[serde(default)]
    pub solid_joinstyle: String,
    #[serde(default)]
    pub solid_capstyle: String,
}

/// Axes configuration.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct AxesConfig {
    #[serde(default)]
    pub facecolor: String,
    #[serde(default)]
    pub edgecolor: String,
    #[serde(default)]
    pub linewidth: f32,
    #[serde(default)]
    pub axisbelow: bool,
    #[serde(default)]
    pub spines: SpinesConfig,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct SpinesConfig {
    #[serde(default)]
    pub top: bool,
    #[serde(default)]
    pub bottom: bool,
    #[serde(default)]
    pub left: bool,
    #[serde(default)]
    pub right: bool,
}

/// Tick marks configuration.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct TicksConfig {
    #[serde(default)]
    pub direction: String,
    #[serde(default)]
    pub length: f32,
    #[serde(default)]
    pub width: f32,
    #[serde(default)]
    pub color: String,
    #[serde(default)]
    pub pad: f32,
    #[serde(default)]
    pub labels: TickLabelsConfig,
    #[serde(default)]
    pub major: TickGridConfig,
    #[serde(default)]
    pub minor: TickGridConfig,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct TickLabelsConfig {
    #[serde(default)]
    pub display: bool,
    #[serde(default)]
    pub fontsize: f32,
    #[serde(default)]
    pub color: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct TickGridConfig {
    #[serde(default)]
    pub grid: bool,
    #[serde(default)]
    pub style: String,
    #[serde(default)]
    pub color: String,
}

/// Axis label configuration.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct LabelConfig {
    #[serde(default)]
    pub display: bool,
    #[serde(default)]
    pub fontsize: f32,
}

/// Grid configuration.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct GridConfig {
    #[serde(default)]
    pub linewidth: f32,
    #[serde(default)]
    pub alpha: f32,
}

/// Legend configuration.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct LegendConfig {
    #[serde(default)]
    pub position: String,
    #[serde(default)]
    pub fontsize: f32,
    #[serde(default)]
    pub frameon: bool,
    #[serde(default)]
    pub framealpha: f32,
    #[serde(default)]
    pub facecolor: String,
    #[serde(default)]
    pub edgecolor: String,
    #[serde(default)]
    pub numpoints: u32,
    #[serde(default)]
    pub scatterpoints: u32,
    #[serde(default)]
    pub markerscale: f32,
}

/// Title configuration.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct TitleConfig {
    #[serde(default)]
    pub display: bool,
    #[serde(default)]
    pub fontsize: f32,
}

/// Font configuration.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct FontConfig {
    #[serde(default)]
    pub family: String,
    #[serde(default)]
    pub size: f32,
    #[serde(default)]
    pub weight: String,
}

/// Figure configuration.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct FigureConfig {
    #[serde(default)]
    pub figsize: [f32; 2],
    #[serde(default)]
    pub dpi: u32,
    #[serde(default)]
    pub facecolor: String,
    #[serde(default)]
    pub edgecolor: String,
}

/// Output configuration.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct OutputConfig {
    #[serde(default)]
    pub formats: Vec<String>,
    #[serde(default)]
    pub dpi: u32,
    #[serde(default)]
    pub transparent: bool,
    #[serde(default)]
    pub bbox: String,
    #[serde(default)]
    pub pad_inches: f32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = PlotConfig::default();
        assert_eq!(config.lines.linewidth, 1.0);
        assert_eq!(config.lines.palette, "qvis");
        assert_eq!(config.figure.dpi, 100);
    }

    #[test]
    fn test_parse_minimal_toml() {
        // Partial TOML: missing fields get Rust Default values (0, empty, false)
        // Use PlotConfig::default() to get full config.toml values
        let toml = r#"
            [lines]
            linewidth = 3
            palette = "matplotlib"
        "#;

        let config = PlotConfig::from_str(toml).unwrap();
        assert_eq!(config.lines.linewidth, 3.0);
        assert_eq!(config.lines.palette, "matplotlib");
        // Missing fields get Rust Default (0), not config.toml values
        assert_eq!(config.figure.dpi, 0);
    }

    #[test]
    fn test_palette_color() {
        let config = PlotConfig::default();

        // qvis palette first color is forest_green
        let color = config.palette_color(0);
        assert_eq!(color, RGBColor(15, 122, 27));

        // Test wrap-around
        let palette_len = config.active_palette().len();
        let color_wrapped = config.palette_color(palette_len);
        assert_eq!(color_wrapped, RGBColor(15, 122, 27));
    }
}
