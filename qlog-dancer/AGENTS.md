# qlog-dancer/

## OVERVIEW

Visualization/analysis tool for qlog and Chrome netlog files. Parses logs into a `Datastore`, extracts time-series into `SeriesStore`, renders PNG charts (native) or canvas plots (wasm). Outputs HTML/text reports with tabled summaries.

Dual-target: native CLI binary (`main.rs`) + wasm-bindgen web UI (`web.rs`, `#[cfg(target_arch = "wasm32")]`). `crate-type = ["lib", "cdylib"]` -- cdylib is for wasm.

## STRUCTURE

```
src/
  main.rs              CLI entry: parse args via AppConfig, render selected plots, emit report
  lib.rs               Public API: parse_log_file(), PacketType, type aliases
  web.rs               wasm-bindgen exports (851 lines), canvas rendering, JS interop
  config.rs            AppConfig (clap CLI + wasm config), plot toggles, colors
  datastore.rs         Datastore struct (~1985 lines) -- central parsed-log representation
  seriesstore.rs       SeriesStore: extracts plot-ready time-series from Datastore
  wirefilter.rs        Event filtering via cloudflare/wirefilter-engine DSL
  request_stub.rs      Stub types for request-level data
  plots/               Chart rendering (plotters crate)
    mod.rs             PlotParameters, ChartSize, ClampParams, output type enums
    conn_overview.rs   Multi-panel connection overview (cwnd, bytes, rtt, streams)
    congestion_control.rs  CC-specific plot
    conn_flow_control.rs   Connection-level flow control
    packet_sent.rs     Packet-number vs time scatter
    packet_received.rs Received packet scatter
    stream_sparks.rs   Per-stream sparkline grids
    stream_multiplex.rs  Stream multiplexing timeline
    pending.rs         Pending data plot
    rtt.rs             RTT plot
    colors.rs          Color palettes
    minmax.rs          Axis range utilities
  reports/             Output reports
    mod.rs             report() dispatcher
    html.rs            HTML report generation (table_to_html)
    text.rs            Plain-text summary
    events.rs          Event-level report details
  trackers/            Stateful metric accumulators
    stream_buffer_tracker.rs  Per-stream buffer sizes
    stream_max_tracker.rs     Stream high-water marks
index.html, *.js, *.css   Web UI assets (crate root, non-standard location)
```

## WHERE TO LOOK

| Task | File |
|------|------|
| Add new plot type | `src/plots/` -- add module, wire into `main.rs` + `web.rs` |
| Change parsed fields | `src/datastore.rs` -- all log-to-struct extraction |
| Add series for plotting | `src/seriesstore.rs` |
| Modify event filters | `src/wirefilter.rs` (wirefilter-engine DSL) |
| CLI args / config | `src/config.rs` (AppConfig, clap) |
| Wasm API surface | `src/web.rs` (`#[wasm_bindgen]` exports) |
| Report formatting | `src/reports/` |

## NOTES

- Native build requires system libs: **libexpat, freetype, fontconfig** (plotters SVG/bitmap backends).
- Wasm uses `plotters-canvas` backend -- canvas rendering, no system deps.
- `wirefilter-engine` pinned to specific git rev, not on crates.io.
- Log format auto-detection: tries qlog JSON, falls back to JSON-SEQ (sqlog), and vice versa.
- `getrandom/wasm_js` feature + `.cargo/config.toml` needed for wasm randomness.
- Web assets (`index.html`, `qlog-dancer-ui.js`, `qlog-dancer.css`) live in crate root, not `src/`.
