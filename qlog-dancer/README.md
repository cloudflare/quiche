qlog-dancer parses logs and generates stats and graphs.

Supports log files in the following formats:

* qlog and sqlog format according to version 0.3 of the datamodel.
* Chrome netlog format

# Pre-requisites

On Debian-based systems, the following additional packages are required:

* cmake
* libexpat1-dev
* libfreetype6-dev
* libfontconfig1-dev

# Generating reports

qlog-dancer can chew through logs and produce reports in text or HTML.

The following example creates a directory named
"chrome-net-export-log.json-report" and places HTML files containing reports
there.

```
$ cargo run --release -- --report-html /path/to/chrome-net-export-log.json
```

The following example prints out text reports to stdout
```
$ cargo run --release -- --report-text /path/to/chrome-net-export-log.json
```

## qlog event table

Both the `--report-text` and `--report-html` options will produce a table
summary of the qlog events contained in the qlog file. This table can be
filtered using the `--qlog-wirefilter` option, which uses
[Wirefilter](https://github.com/cloudflare/wirefilter) for Wireshark-like
expressions and matching behavior. The fields supported are:

* category: A string representing the qlog category of the event
* name: A string representing the qlog event name without category.
* stream_id: An integer representing a QUIC stream ID, that can appear in many
  types of event. A filter based on stream ID will match several events.

Some examples:

* `--qlog-wirefilter 'name != "data_moved" && name != "metrics_updated"'` will
  filter out events with the name `data_moved` and `metrics_updated`
* `--qlog-wirefilter 'category = "http"'` will filter in events belonging to the
  `http` category.
* `--qlog-wirefilter 'any(stream_id[*]==0)'` will filter
  in events that contains a stream ID of 0.
* `--qlog-wirefilter 'any(stream_id[*] in {0 3})'` will filter
  in events that contains a stream ID of either 0 or 3.

When using the `--report-html` option, a table of filtered qlog events in the
provided file will be produced in event-list.html. This includes an in-browser
search capability based on the default [DataTables](https://datatables.net/)
library.

# Generating charts

qlog-dancer can chew through logs and produce charts as PNG images.

By default, this feature is not enabled. Use the `charts` option to enable it,
use `-h` for a description of the options.

The following example creates a directory named "file.sqlog-charts" and places
images there.

```
$ cargo run --release -- --charts all /path/to/file.sqlog
```

There are several types of chart including:

* file.sqlog-conn-overview.png
  * Congestion control, RTT, and combined stream data plotting
* file.sqlog-conn-spark-absolute.png
  * Plot individual charts for stream data buffering and STREAM frame emission,
    x-axis (representing time) intercept is test run start time
* file.sqlog-conn-spark-relative.png
  * Plot individual charts for stream data buffering and STREAM frame emission,
    x-axis (representing time) intercept is when stream buffering started

qlog-dancer uses the plotters library, which has interpolated line series. We
attempt to work around this in a pre-processing step but be careful to check
line series rending matches the expectations of underlying daa types.

# Filtering Chrome netlogs

Netlogs can contain events related to many connections. The `netlog-filter`
option is a comma-seperated list of hostnames to filter in to netlog analysis.
By default, all hostname are analyzed.

```
$ cargo run --release -- --netlog-filter "example.com" /path/to/chrome-net-export-log.json
```

# The qlog-dancer web app

qlog-dancer also provides some capabilities as a web app via WASM. Some of the
file handling and loading code is different but otherwise it still uses plotters
to generate charts that are then drawn to a canvas on a web page. This provides
support for interactive elements with the plots.

For local development:

1. Install [wasm-pack](https://github.com/rustwasm/wasm-pack).
2. From the qlog-dancer directory, run `wasm-pack build --target=web`. This
   generates files into a `pkg` subdirectory.
3. Launch a webserver of any kind that can serve the checked in `index.html` and
   the generated file such `pkg/qlog_dancer.js`. For example, the following works just fine

```
path/to/qlog-dancer/qlog-dancer$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/)
```
4. Connect to your webserver and click the "Choose file" button to load a file
   and render some plots. E.g. `http://localhost:8000/` (no need to type
   index.html since the example server deals with that itself)

