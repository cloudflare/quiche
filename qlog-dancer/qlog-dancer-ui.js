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

import  {new_qlog_dancer} from './pkg/qlog_dancer.js';

let qlog_dancer = null;
let currentRectangle = null;

const OVERVIEW_CANVAS = "overview_canvas";
const CC_CANVAS = "cc_canvas";
const RTT_CANVAS = "rtt_canvas";
const FLOW_CONTROL_CANVAS = "flow_control_canvas";
const PKT_RX_CANVAS = "pkt-rx-canvas";
const PKT_TX_CANVAS = "pkt-tx-canvas";
const PKT_TX_COUNTS_CANVAS = "pkt-tx-counts-canvas";
const PKT_TX_DELTA_CANVAS = "pkt-tx-delta-canvas";
const PKT_TX_PACING_CANVAS = "pkt-tx-pacing-canvas";
const STREAM_MULTIPLEX_CANVAS = "stream-multiplex-canvas";
const STREAM_ABS_DL_CANVAS = "abs_dl_canvas";
const STREAM_REL_DL_CANVAS = "rel_dl_canvas"
const STREAM_ABS_UL_CANVAS = "abs_ul_canvas"
const STREAM_REL_UL_CANVAS = "rel_ul_canvas"
const PENDING_CANVAS = "pending_canvas"

let canvasMap = new Map();
canvasMap.set(OVERVIEW_CANVAS, {show_legend: false, x_start: null, x_end: null});
canvasMap.set(CC_CANVAS, {show_legend: false, x_start: null, x_end: null});
canvasMap.set(RTT_CANVAS, {show_legend: false, x_start: null, x_end: null});
canvasMap.set(FLOW_CONTROL_CANVAS, {show_legend: false, x_start: null, x_end: null});
canvasMap.set(PKT_RX_CANVAS, {show_legend: false, x_start: null, x_end: null});
canvasMap.set(PKT_TX_CANVAS, {show_legend: false, x_start: null, x_end: null});
canvasMap.set(PKT_TX_COUNTS_CANVAS, {show_legend: false, x_start: null, x_end: null});
canvasMap.set(PKT_TX_DELTA_CANVAS, {show_legend: false, x_start: null, x_end: null});
canvasMap.set(PKT_TX_PACING_CANVAS, {show_legend: false, x_start: null, x_end: null});
canvasMap.set(STREAM_MULTIPLEX_CANVAS, {show_legend: false, x_start: null, x_end: null});
canvasMap.set(STREAM_ABS_DL_CANVAS, {show_legend: false, x_start: null, x_end: null});
canvasMap.set(STREAM_REL_DL_CANVAS, {show_legend: false, x_start: null, x_end: null});
canvasMap.set(STREAM_ABS_UL_CANVAS, {show_legend: false, x_start: null, x_end: null});
canvasMap.set(STREAM_REL_UL_CANVAS, {show_legend: false, x_start: null, x_end: null});
canvasMap.set(PENDING_CANVAS, {show_legend: false, x_start: null, x_end: null});


function setupDarkmode() {
    window.addEventListener("load", (event) => {

        let prefers = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
        let html = document.querySelector('html');

        html.classList.add(prefers);
        html.setAttribute('data-bs-theme', prefers);
    });
}

let showFcLegend = false;
let showPktRxLegend = false;

function setupCanvas(div_id, canvas_id) {
    const div = document.getElementById(div_id);
    const dpr = window.devicePixelRatio || 1.0;
    //const aspectRatio = canvas.width / canvas.height;
    //const size = canvas.parentNode.offsetWidth * 0.8;
    //canvas.style.width = size + "px";
    //canvas.style.height = size / aspectRatio + "px";
    //canvas.width = size;
    //canvas.height = size / aspectRatio;

    // Original dimensions
    //const baseWidth = 600;
    //const baseHeight = 400;

    // Adjust for DPR
    //div.style.width = `${baseWidth / dpr}px`;
    //div.style.height = `${baseHeight / dpr}px`;

        div.style.width = '100vw';

        const canvas = document.getElementById(div_id);
        canvas.width = div.clientWidth;
        canvas.height = div.clientHeight;
}

async function loadLog(event) {

    if (!event || !event.target || !event.target.files || event.target.files.length === 0) {
        console.log("big problem happened loading log");
        return;
    }

    let file = event.target.files[0];
    console.log(`Loading ${file.name}`);
    var loading = document.getElementById("loading");
    loading.style.display = "block";

    qlog_dancer = new_qlog_dancer(file.name);

    const start = Date.now();
    const reader = file.stream().getReader();
    while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        qlog_dancer.process_chunk(value);
    }
    const end = Date.now();
    console.log(`Log read duration: ${end - start} ms`);

    const ds_pop_start = Date.now();
    qlog_dancer.populate_datastore();
    const ds_pop_end = Date.now();
    console.log(`populate datastore duration: ${ds_pop_end - ds_pop_start} ms`);

    const packets_sent = qlog_dancer.total_packets_sent();
    console.log(`packet sent events total = ${packets_sent}`);

    const start_pop = Date.now();
    qlog_dancer.populate_seriesstore();
    const end_pop = Date.now();
    console.log(`data processing of charts duration: ${end_pop - start_pop} ms`);

    //setupCanvas("overview_container", "overview_canvas")

    // Default to draw overview page
    toggleOverview()

    var comp = document.getElementById("load-complete");
    loading.style.display = "none";
    comp.style.display = "block";
}

function toggleElem(e) {
    if (e.style.display === "none") {
    e.style.display = "block";
    return true;
    } else {
    e.style.display = "none";
    return false;
    }
}

function toggleLegend(event) {
    let canvas_id = findCanvasIdInDiv(event);
    let canvas = canvasMap.get(canvas_id);

    if (canvas.show_legend) {
        canvas.show_legend = false;
    } else {
        canvas.show_legend = true;
    }

    redrawByCanvasId(canvas_id);
}

function redrawByCanvasId(canvas_id) {
    let sub_start_draw = Date.now();
    let canvas = canvasMap.get(canvas_id);

    if (canvas_id === OVERVIEW_CANVAS) {
        qlog_dancer.draw_connection_overview(OVERVIEW_CANVAS, canvas.show_legend, canvas.x_start, canvas.x_end);
    } else if (canvas_id === RTT_CANVAS) {
        qlog_dancer.draw_rtt_plot(RTT_CANVAS, canvas.show_legend, canvas.x_start, canvas.x_end);
    } else if (canvas_id === CC_CANVAS) {
        qlog_dancer.draw_cc_plot(CC_CANVAS, canvas.show_legend, canvas.x_start, canvas.x_end);
    } else if (canvas_id === FLOW_CONTROL_CANVAS) {
        drawFlowControl(true);
    } else if (canvas_id === PKT_RX_CANVAS) {
        drawPacketReceived(true);
    } else if (canvas_id === PKT_TX_CANVAS) {
        qlog_dancer.draw_packet_sent_plot(PKT_TX_CANVAS, canvas.show_legend, canvas.x_start, canvas.x_end);
    } else if (canvas_id === PKT_TX_COUNTS_CANVAS) {
        qlog_dancer.draw_packet_sent_lost_delivered_count_plot(PKT_TX_COUNTS_CANVAS, canvas.show_legend, canvas.x_start, canvas.x_end);
    }else if (canvas_id === PKT_TX_DELTA_CANVAS) {
        qlog_dancer.draw_packet_sent_delta_plot(PKT_TX_DELTA_CANVAS, canvas.show_legend, canvas.x_start, canvas.x_end);
    } else if (canvas_id === PKT_TX_PACING_CANVAS) {
        qlog_dancer.draw_packet_sent_pacing_plot(PKT_TX_PACING_CANVAS, canvas.show_legend, canvas.x_start, canvas.x_end);
    } else if (canvas_id === "stream-multiplex-canvas") {
        drawStreamMultiplex(true);
    } else if (canvas_id === "abs_dl_canvas" ||
                canvas_id === "abs_ul_canvas" ||
                canvas_id === "rel_dl_canvas" ||
                canvas_id === "rel_ul_canvas") {
        drawSparks(true)
    } else if(canvas_id === "pending_canvas") {
        drawPending(true)
    } else {
        console.log("unknown canvas id is " + canvas_id)
    }

    console.log(`${canvas_id} draw duration: ${Date.now() - sub_start_draw} ms`);
}

function drawOverview(resize) {
    if (resize || !window.overviewDrawn) {
        let sub_start_draw = Date.now();
        let overview_canvas = canvasMap.get(OVERVIEW_CANVAS);
        qlog_dancer.draw_connection_overview(OVERVIEW_CANVAS, overview_canvas.show_legend, overview_canvas.x_start, overview_canvas.x_end);
        let cc_canvas = canvasMap.get(CC_CANVAS);
        qlog_dancer.draw_cc_plot(CC_CANVAS, cc_canvas.show_legend, cc_canvas.x_start, cc_canvas.x_end);
        let rtt_canvas = canvasMap.get(RTT_CANVAS);
        qlog_dancer.draw_rtt_plot(RTT_CANVAS, cc_canvas.show_legend, rtt_canvas.x_start, cc_canvas.x_end);
        console.log(`complete conn overview draw duration: ${Date.now() - sub_start_draw} ms`);
        window.overviewDrawn = true;
        setupCanvasInteraction(OVERVIEW_CANVAS);
        setupCanvasInteraction(CC_CANVAS);
        setupCanvasInteraction(RTT_CANVAS);
    } else {
        console.log("no need to redraw overview")
    }
}

function drawFlowControl(resize) {
    if (resize || !window.flowControlDrawn) {
        let sub_start_draw = Date.now();
        qlog_dancer.draw_flow_control(FLOW_CONTROL_CANVAS, showFcLegend);
        console.log(`flow control draw duration: ${Date.now() - sub_start_draw} ms`);
        window.flowControlDrawn = true;
        setupCanvasInteraction(FLOW_CONTROL_CANVAS);
    } else {
    console.log("no need to redraw flow control")
    }
}

function drawPacketReceived(resize) {
    if (resize || !window.packetReceivedDrawn) {
        let sub_start_draw = Date.now();
        qlog_dancer.draw_packet_received(PKT_RX_CANVAS, showPktRxLegend);
        console.log(`packet received draw duration: ${Date.now() - sub_start_draw} ms`);
        window.packetReceivedDrawn = true;
        setupCanvasInteraction(PKT_RX_CANVAS);
    } else {
    console.log("no need to redraw pkt rx")
    }
}

function drawPacketSent(resize) {
    if (resize || !window.packetSentDrawn) {
        let sub_start_draw = Date.now();
        let pkt_sent_canvas = canvasMap.get(PKT_TX_CANVAS);
        qlog_dancer.draw_packet_sent_plot(PKT_TX_CANVAS, pkt_sent_canvas.show_legend, pkt_sent_canvas.x_start, pkt_sent_canvas.x_end);
        let pkt_sent_counts_canvas = canvasMap.get(PKT_TX_COUNTS_CANVAS);
        qlog_dancer.draw_packet_sent_lost_delivered_count_plot(PKT_TX_COUNTS_CANVAS, pkt_sent_counts_canvas.show_legend, pkt_sent_counts_canvas.x_start, pkt_sent_counts_canvas.x_end);
        let pkt_sent_delta_canvas = canvasMap.get(PKT_TX_DELTA_CANVAS);
        qlog_dancer.draw_packet_sent_delta_plot(PKT_TX_DELTA_CANVAS, pkt_sent_delta_canvas.show_legend, pkt_sent_delta_canvas.x_start, pkt_sent_delta_canvas.x_end);
        let pkt_sent_pacing_canvas = canvasMap.get(PKT_TX_PACING_CANVAS);
        qlog_dancer.draw_packet_sent_pacing_plot(PKT_TX_PACING_CANVAS, pkt_sent_pacing_canvas.show_legend, pkt_sent_pacing_canvas.x_start, pkt_sent_pacing_canvas.x_end);
        console.log(`packet sent draw duration: ${Date.now() - sub_start_draw} ms`);
        window.packetSentDrawn = true;
        setupCanvasInteraction(PKT_TX_CANVAS);
        setupCanvasInteraction(PKT_TX_COUNTS_CANVAS);
        setupCanvasInteraction(PKT_TX_DELTA_CANVAS);
        setupCanvasInteraction(PKT_TX_PACING_CANVAS);
    } else {
    console.log("no need to redraw pkt tx")
    }
}

function drawStreamMultiplex(resize) {
    if (resize) {
        let sub_start_draw = Date.now();
        qlog_dancer.draw_stream_multiplexing("stream-multiplex-canvas");
        console.log(`stream multiplex draw duration: ${Date.now() - sub_start_draw} ms`);
        return;
    }

    if (!window.streamMultiplexDrawn) {
        //setupCanvas("stream-multiplex-canvas");
        let sub_start_draw = Date.now();
        qlog_dancer.draw_stream_multiplexing("stream-multiplex-canvas");
        console.log(`stream multiplex draw duration: ${Date.now() - sub_start_draw} ms`);
        window.streamMultiplexDrawn = true;
    } else {
    console.log("no need to redraw stream multiplex")
    }
}

function drawSparks(resize) {
    if (resize) {
        let sub_start_draw = Date.now();
        qlog_dancer.draw_sparks("abs_dl_canvas", "rel_dl_canvas", "abs_ul_canvas", "rel_ul_canvas")
        console.log(`sparks draw duration: ${Date.now() - sub_start_draw} ms`);
        return;
    }

    if (!window.streamSparksDrawn) {
        let sub_start_draw = Date.now();
        qlog_dancer.draw_sparks("abs_dl_canvas", "rel_dl_canvas", "abs_ul_canvas", "rel_ul_canvas")
        console.log(`sparks draw duration: ${Date.now() - sub_start_draw} ms`);
        window.streamSparksDrawn = true;
    } else {
        console.log("no need to redraw")
    }
}

function drawPending(resize) {
    if (resize) {
        let sub_start_draw = Date.now();
        qlog_dancer.draw_pending("pending_canvas");
        console.log(`pending draw duration: ${Date.now() - sub_start_draw} ms`);
        return;
    }

    if (!window.pendingDrawn) {
        let sub_start_draw = Date.now();
        qlog_dancer.draw_pending("pending_canvas");
        console.log(`pending draw duration: ${Date.now() - sub_start_draw} ms`);
        window.pendingDrawn = true;
    } else {
        console.log("no need to redraw")
    }
}

function toggleOverview() {
    if (document.getElementById("overview-btn").innerText == "Overview shown") {
        document.getElementById("overview-btn").innerText = "Overview hidden";
    } else {
        document.getElementById("overview-btn").innerText = "Overview shown";
    }
    if (toggleElem(document.getElementById("overview"))) {
        drawOverview(false)
    }
}

function toggleFlowControl() {
    if (document.getElementById("flow-control-btn").innerText == "Flow control shown") {
        document.getElementById("flow-control-btn").innerText = "Flow control hidden";
    } else {
        document.getElementById("flow-control-btn").innerText = "Flow control shown";
    }
    if (toggleElem(document.getElementById("flow-control"))) {
        drawFlowControl()
    }
}

function togglePacketReceived() {
    if (document.getElementById("pkt-rx-btn").innerText == "Packet rx shown") {
        document.getElementById("pkt-rx-btn").innerText = "Packet rx hidden";
    } else {
        document.getElementById("pkt-rx-btn").innerText = "Packet rx shown";
    }
    if (toggleElem(document.getElementById("pkt-rx"))) {
        drawPacketReceived()
    }
}

function togglePacketSent() {
    if (document.getElementById("pkt-tx-btn").innerText == "Packet tx shown") {
        document.getElementById("pkt-tx-btn").innerText = "Packet tx hidden";
    } else {
        document.getElementById("pkt-tx-btn").innerText = "Packet tx shown";
    }
    if (toggleElem(document.getElementById("pkt-tx"))) {
        drawPacketSent()
    }
}

function toggleStreamMultiplex() {
    if (document.getElementById("stream-multiplex-btn").innerText == "Stream multiplexing shown") {
        document.getElementById("stream-multiplex-btn").innerText = "Stream multiplexing hidden";
    } else {
        document.getElementById("stream-multiplex-btn").innerText = "Stream multiplexing shown";
    }
    if (toggleElem(document.getElementById("stream-multiplex"))) {
        drawStreamMultiplex()
    }
}

function togglePending() {
    if (document.getElementById("pending-btn").innerText == "Stream pending shown") {
        document.getElementById("pending-btn").innerText = "Stream pending hidden";
    } else {
        document.getElementById("pending-btn").innerText = "Stream pending shown";
    }
    if (toggleElem(document.getElementById("pending"))) {
        drawPending()
    }
}

function toggleSparks() {
    if (document.getElementById("sparks-btn").innerText == "Stream sparks shown") {
        document.getElementById("sparks-btn").innerText = "Stream sparks hidden";
    } else {
        document.getElementById("sparks-btn").innerText = "Stream sparks shown";
    }
    // Base redraw decision on just one, since they are all kept in sync
    let redraw = toggleElem(document.getElementById("abs-dl"));
    toggleElem(document.getElementById("rel-dl"));
    toggleElem(document.getElementById("abs-ul"));
    toggleElem(document.getElementById("rel-ul"));
    if (redraw) {
        drawSparks()
    }
}

let recalc_events = true;

function toggleEventList() {
if (document.getElementById("event-list-btn").innerText == "Events shown") {
        document.getElementById("event-list-btn").innerText = "Events hidden";
    } else {
        document.getElementById("event-list-btn").innerText = "Events shown";
    }
    if (toggleElem(document.getElementById("events-top-container"))) {

    }
}

function render_events_table() {
    if (recalc_events) {
        var loading = document.getElementById("events-loading");
        loading.style.display = "block";

        // Use intersection observer to detect when div is actually visible
        const observer = new IntersectionObserver((entries) => {
            if (entries[0].isIntersecting) {
                observer.disconnect();

                // Div is definitely visible now
                setTimeout(() => {
                    populate_event_table();

                    setupTable();
                    loading.style.display = "none";
                }, 0);
            }
        });

        observer.observe(loading);


    }
}

function populate_event_table() {
    if (recalc_events) {
        qlog_dancer.populate_event_table("events-container");
        recalc_events = false;

    }
}

function setupTable() {
    new DataTable('table.log-dancer-table',
        {
            paging: false,
            dom: '<"center" flpti  >'
        });
}

function findCanvasIdInDiv(event) {
    let canvas_id = null;
    // Get the div where the click happened
    const clickedDiv = event.target.closest('div');

    if (clickedDiv) {
        // Find the canvas element within the div
        const canvas = clickedDiv.querySelector('canvas');

        if (canvas && canvas.id) {
            return canvas.id;
        } else {
            console.log('No canvas with ID found in the clicked div');
            return null;
        }
    } else {
        console.log('No parent div found');
        return null ;
    }
}

function resetZoom(event) {
    console.log("resetty");

    let canvas_id = findCanvasIdInDiv(event);
    let canvas = canvasMap.get(canvas_id);
    canvas.x_start = null;
    canvas.x_end = null;
    redrawByCanvasId(canvas_id);
}

const input = document.querySelector("input");
input.addEventListener("input", loadLog);

document.getElementById("overview-btn").addEventListener("click", toggleOverview);
document.getElementById("flow-control-btn").addEventListener("click", toggleFlowControl);
document.getElementById("pkt-rx-btn").addEventListener("click", togglePacketReceived);
document.getElementById("pkt-tx-btn").addEventListener("click", togglePacketSent);
document.getElementById("stream-multiplex-btn").addEventListener("click", toggleStreamMultiplex);
document.getElementById("sparks-btn").addEventListener("click", toggleSparks);
document.getElementById("pending-btn").addEventListener("click", togglePending);
document.getElementById("event-list-btn").addEventListener("click", toggleEventList);
document.getElementById("render-events-btn").addEventListener("click", render_events_table);

document.getElementById("overview-reset-btn").addEventListener("click", resetZoom);
document.getElementById("cc-reset-btn").addEventListener("click", resetZoom);
document.getElementById("rtt-reset-btn").addEventListener("click", resetZoom);
document.getElementById("pkt-tx-reset-btn").addEventListener("click", resetZoom);
document.getElementById("pkt-tx-counts-reset-btn").addEventListener("click", resetZoom);
document.getElementById("pkt-tx-delta-reset-btn").addEventListener("click", resetZoom);
document.getElementById("pkt-tx-pacing-reset-btn").addEventListener("click", resetZoom);

document.getElementById("overview-toggle-legend-btn").addEventListener("click", toggleLegend);
document.getElementById("cc-toggle-legend-btn").addEventListener("click", toggleLegend);
document.getElementById("rtt-toggle-legend-btn").addEventListener("click", toggleLegend);
document.getElementById("pkt-tx-toggle-legend-btn").addEventListener("click", toggleLegend);
document.getElementById("pkt-tx-counts-toggle-legend-btn").addEventListener("click", toggleLegend);
document.getElementById("pkt-tx-delta-toggle-legend-btn").addEventListener("click", toggleLegend);
document.getElementById("pkt-tx-pacing-toggle-legend-btn").addEventListener("click", toggleLegend);

function setupCanvasResizer(canvas_id) {
    const canvas = document.getElementById(canvas_id);
    const container = canvas.parentElement;
    const handle = container.querySelector('.resize-handle');
    const ctx = canvas.getContext('2d');

    // Variables to track resize state
    let isResizing = false;
    let startX, startY, startWidth, startHeight;
    let canvas_id_me = canvas_id;

    // Mouse down event on resize handle
    handle.addEventListener('mousedown', (e) => {
        isResizing = true;
        startX = e.clientX;
        startY = e.clientY;
        startWidth = canvas.width;
        startHeight = canvas.height;
        document.addEventListener('mousemove', onMouseMove);
        document.addEventListener('mouseup', onMouseUp);
        e.preventDefault();
    });

    // Mouse move event for resizing
    function onMouseMove(e) {
        if (!isResizing) return;

        const newWidth = startWidth + (e.clientX - startX);
        const newHeight = startHeight + (e.clientY - startY);

        // Ensure minimum size
        if (newWidth > 50 && newHeight > 50) {
            canvas.width = newWidth;
            canvas.height = newHeight;

        }
    }

    // Mouse up event to stop resizing
    function onMouseUp() {
        isResizing = false;
        redrawByCanvasId(canvas_id_me);

        document.removeEventListener('mousemove', onMouseMove);
        document.removeEventListener('mouseup', onMouseUp);
    }
}

// Setup all canvas'
canvasMap.forEach((value, key) => {
    setupCanvasResizer(key);
});

function canvasToPlotCoords(canvasX, canvasY, chartBounds, plotRanges) {
    const plotPixelX = canvasX - chartBounds.left;
    const plotPixelY = canvasY - chartBounds.top;

    if (plotPixelX < 0 || plotPixelX > chartBounds.width ||
        plotPixelY < 0 || plotPixelY > chartBounds.height) {
        return null;
    }

    const normalizedX = plotPixelX / chartBounds.width;
    const normalizedY = plotPixelY / chartBounds.height;

    const plotX = plotRanges.x_min + normalizedX * (plotRanges.x_max - plotRanges.x_min);
    const plotY = plotRanges.y_max - normalizedY * (plotRanges.y_max - plotRanges.y_min);

    return { x: plotX, y: plotY };
}

function setupCanvasInteraction(canvasId) {
    const canvas = document.getElementById(canvasId);
    const container = canvas.parentElement;
    const tooltip = document.getElementById('tooltip');
    let [chartBounds, plotRanges] = qlog_dancer.get_chart_info(canvasId);
    let isMouseOverCanvas = false;
    let isDrawingRect = false;
    let startX, startY, startXPlot, startYPlot;

    function tidyCurrentRectangle() {
        isDrawingRect = false;
        if (currentRectangle) {
        currentRectangle.remove();
        }
        currentRectangle = null;
    }

    canvas.addEventListener('mousedown', (e) => {
        isDrawingRect = true;
        const rect = canvas.getBoundingClientRect();
        startX = e.clientX - rect.left;
        startY = e.clientY - rect.top;

        let [chartBounds, plotRanges] = qlog_dancer.get_chart_info(canvasId);
        const plotCoords = canvasToPlotCoords(startX, startY, chartBounds, plotRanges);
        if (plotCoords) {
        startXPlot = plotCoords.x;
        startYPlot = plotCoords.y;

        // Create a new rectangle div
        currentRectangle = document.createElement('div');
        currentRectangle.className = 'rectangle';
        currentRectangle.style.left = startX + 'px';
        currentRectangle.style.top = startY + 'px';
        currentRectangle.style.width = '0px';
        currentRectangle.style.height = '0px';
        container.appendChild(currentRectangle);
        }
    });

        // Mouse move handler for live tooltip
        canvas.addEventListener('mousemove', function(event) {
            const rect = canvas.getBoundingClientRect();
            const canvasX = event.clientX - rect.left;
            const canvasY = event.clientY - rect.top;

            let [chartBounds, plotRanges] = qlog_dancer.get_chart_info(canvasId);
            const plotCoords = canvasToPlotCoords(canvasX, canvasY, chartBounds, plotRanges);

            if (plotCoords) {
                isMouseOverCanvas = true;
                updateTooltip(event, plotCoords, tooltip);
            } else {
                hideTooltip(tooltip);
                isMouseOverCanvas = false;
            }

            if (isDrawingRect && currentRectangle) {
                // Calculate rectangle dimensions
                const width = Math.abs(canvasX - startX);
                const height = Math.abs(canvasY - startY);

                // Update rectangle position and size
                currentRectangle.style.left = Math.min(startX, canvasX) + 'px';
                currentRectangle.style.top = Math.min(startY, canvasY) + 'px';
                currentRectangle.style.width = width + 'px';
                currentRectangle.style.height = height + 'px';
            }
        });

        // Hide tooltip when mouse leaves canvas
        canvas.addEventListener('mouseleave', function() {
            hideTooltip(tooltip);
            isMouseOverCanvas = false;
            tidyCurrentRectangle();

        });

        canvas.addEventListener('mouseup', function() {
            const rect = canvas.getBoundingClientRect();
            const canvasX = event.clientX - rect.left;
            const canvasY = event.clientY - rect.top;

            let [chartBounds, plotRanges] = qlog_dancer.get_chart_info(canvasId);
            const plotCoords = canvasToPlotCoords(canvasX, canvasY, chartBounds, plotRanges);

            if (plotCoords) {
                let canvas_data = canvasMap.get(canvas.id);
                canvas_data.x_start = startXPlot.toFixed(1);
                canvas_data.x_end = plotCoords.x.toFixed(1);

                redrawByCanvasId(canvas.id);

                console.log(`Start at: (${startXPlot.toFixed(1)}, ${startYPlot.toFixed(1)}), end at (${plotCoords.x.toFixed(1)}, ${plotCoords.y.toFixed(1)})`);
            }

            isDrawingRect = false;
            tidyCurrentRectangle();


        });

        // Show tooltip when mouse enters canvas
        canvas.addEventListener('mouseenter', function() {
            isMouseOverCanvas = true;
        });
}

function updateTooltip(event, plotCoords, tooltip) {
    // Update tooltip content
    tooltip.innerHTML = `
        <div class="tooltip-content">
            <div class="coord-line">X: <span class="coord-value">${plotCoords.x.toFixed(0)}</span></div>
            <div class="coord-line">Y: <span class="coord-value">${plotCoords.y.toFixed(0)}</span></div>
        </div>
    `;

    // Position tooltip near mouse cursor
    const tooltipOffset = 15;
    let tooltipX = event.pageX + tooltipOffset;
    let tooltipY = event.pageY - tooltipOffset;

    // Prevent tooltip from going off-screen
    const tooltipRect = tooltip.getBoundingClientRect();
    const viewportWidth = window.innerWidth;
    const viewportHeight = window.innerHeight;

    // Adjust horizontal position if tooltip would go off right edge
    if (tooltipX + tooltipRect.width > viewportWidth) {
        tooltipX = event.pageX - tooltipRect.width - tooltipOffset;
    }

    // Adjust vertical position if tooltip would go off top edge
    if (tooltipY < 0) {
        tooltipY = event.pageY + tooltipOffset;
    }

    tooltip.style.left = tooltipX + 'px';
    tooltip.style.top = tooltipY + 'px';
    tooltip.style.display = 'block';
    tooltip.style.opacity = '1';
}

function hideTooltip(tooltip) {
    tooltip.style.display = 'none';
    tooltip.style.opacity = '0';
}