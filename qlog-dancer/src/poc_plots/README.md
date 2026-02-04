# POC Plots - Config-Driven QLOG Visualization

A proof-of-concept for matplotlib-style config-driven plotting of QLOG data.

## Features

- **Single source of truth**: All styling comes from `config.toml` - no recompilation needed
- **Real sqlog support**: Parses Cloudflare extension fields (`cf_send_rate`, `cf_ack_rate`, `cf_delivery_rate`)
- **Auto-statistics**: Series data tracks min/max automatically via `SeriesData<T>`
- **Color palettes**: Supports `qvis` (default), `matplotlib`, `palette99`, and `palette9999` (accessibility)

## Usage

```bash
# With real sqlog file
cargo run -p qlog-dancer --bin poc_plotter -- \
  --input /path/to/file.sqlog \
  --extend -o /tmp/pacing_real.png

# With matplotlib palette (no recompilation)
cargo run -p qlog-dancer --bin poc_plotter -- \
  --input <sqlog_file> --palette matplotlib -o /tmp/pacing_matplotlib.png

# With custom config file
cargo run -p qlog-dancer --bin poc_plotter -- \
  --input <sqlog_file> --config my_custom_config.toml -o output.png

# Demo mode (synthetic data)
cargo run -p qlog-dancer --bin poc_plotter -- --demo -o /tmp/demo.png
```

## CLI Options

| Option | Description |
|--------|-------------|
| `-i, --input <PATH>` | Path to sqlog file (required unless `--demo`) |
| `-c, --config <PATH>` | Path to custom config.toml |
| `-o, --output <PATH>` | Output PNG path (default: `pacer_plot.png`) |
| `-p, --palette <NAME>` | Override palette: `qvis`, `matplotlib`, `palette99`, or `palette9999` |
| `--extend` | Extend lines to full plot width |
| `--demo` | Generate demo data instead of reading sqlog |

## Configuration

Edit `config.toml` to customize:

- **Palettes**: Define custom color palettes
- **Lines**: Line width, style, alpha
- **Axes**: Frame/spines, edge colors
- **Ticks**: Direction, size, label fonts
- **Labels**: X/Y axis label fonts
- **Legend**: Position, font size, frame
- **Title**: Display, font size
- **Figure**: Size, DPI, background

## Color Palettes

Four built-in palettes are available:

| Palette | Description |
|---------|-------------|
| `qvis` | Default qvis colors (forest green, purple, taupe, etc.) |
| `matplotlib` | Matplotlib's default color cycle (C0-C9) |
| `palette99` | Plotters' Palette99 (99% color vision accessible) |
| `palette9999` | Plotters' Palette9999 (99.99% color vision accessible) |

### Using a Palette

Via CLI:
```bash
cargo run -p qlog-dancer --bin poc_plotter -- --demo --palette palette99
```

Or in `config.toml`:
```toml
[lines]
palette = "matplotlib"
```

### Custom Palettes

Define custom palettes in `config.toml`:

```toml
[palettes.my_custom]
colors = [
    [255, 0, 0],    # red
    [0, 255, 0],    # green
    [0, 0, 255],    # blue
]

[lines]
palette = "my_custom"
```

## Architecture

```
poc_plots/
├── config.rs      # TOML config parsing (embeds config.toml)
├── config.toml    # Single source of truth for styling
├── theme.rs       # Plotters integration (ColorCycle, PlotTheme)
├── series_data.rs # SeriesData<T> with auto min/max tracking
└── modules/
    └── pacer.rs   # Pacing rate plot implementation
```