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

use packet_sent::draw_packet_sent_received_plot;
use plotters::prelude::*;

use crate::plots::*;

use crate::datastore::Datastore;
use crate::seriesstore::SeriesStore;

pub fn plot_packet_received(
    params: &PlotParameters, filename: &str, ss: &SeriesStore, ds: &Datastore,
    ty: &ChartOutputType,
) {
    let chart_config = ChartConfig {
        title: "packet-received".into(),
        input_filename: filename.into(),
        clamp: params.clamp.clone(),
        app_proto: ds.application_proto,
        host: ds.host.clone(),
        session_id: ds.session_id,
        ty: ty.clone(),
    };

    chart_config.init_chart_dir();

    #[cfg(not(target_arch = "wasm32"))]
    let chart_path = chart_config.chart_filepath();

    #[cfg(not(target_arch = "wasm32"))]
    let root = make_chart_bitmap_area(
        &chart_path,
        params.chart_size,
        params.colors,
        params.chart_margin,
    );

    #[cfg(target_arch = "wasm32")]
    let canvas_id: String = chart_config.canvas_id().unwrap_or_default();

    #[cfg(target_arch = "wasm32")]
    let root =
        make_chart_canvas_area(&canvas_id, params.colors, params.chart_margin);

    let (raw_timings, _remainder) = root.split_vertically((60).percent());

    draw_packet_sent_received_plot(false, filename, params, ss, &raw_timings);
}
