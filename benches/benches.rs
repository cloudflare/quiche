// Copyright (C) 2018-2019, Cloudflare, Inc.
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

#[macro_use]
extern crate criterion;

use ring::rand::*;

use criterion::Criterion;

fn handshake(c: &mut Criterion) {
    let mut buf = [0; 65535];

    let mut config = make_bench_config();

    c.bench_function("handshake", move |b| {
        b.iter(|| {
            let mut pipe =
                quiche::testing::Pipe::with_config(&mut config).unwrap();
            pipe.handshake(&mut buf).unwrap();
        })
    });
}

fn stream(c: &mut Criterion) {
    let mut buf = [0; 65535];

    let mut config = make_bench_config();

    let mut pipe = quiche::testing::Pipe::with_config(&mut config).unwrap();
    pipe.handshake(&mut buf).unwrap();

    let mut send_buf = vec![0; 5_000_000];
    SystemRandom::new().fill(&mut send_buf[..]).unwrap();

    let mut recv_buf = vec![0; send_buf.len()];

    c.bench_function_over_inputs(
        "stream",
        move |b, &&size| {
            b.iter(|| {
                pipe.client
                    .stream_send(4, &send_buf[..size], false)
                    .unwrap();

                let mut recv_len = 0;

                while recv_len < size {
                    pipe.flush_client(&mut buf).unwrap();

                    let (len, _) = pipe
                        .server
                        .stream_recv(4, &mut recv_buf[recv_len..])
                        .unwrap();
                    recv_len += len;

                    pipe.flush_server(&mut buf).unwrap();
                }

                assert_eq!(recv_len, size);
                assert_eq!(&recv_buf[..size], &send_buf[..size]);
            })
        },
        &[128_000, 256_000, 512_000, 1_000_000, 5_000_000],
    );
}

fn http3(c: &mut Criterion) {
    let mut buf = [0; 65535];

    let mut config = make_bench_config();

    let mut h3_config = quiche::h3::Config::new().unwrap();

    let mut s =
        quiche::h3::testing::Session::with_configs(&mut config, &mut h3_config)
            .unwrap();
    s.handshake().unwrap();

    let mut send_buf = vec![0; 5_000_000];
    SystemRandom::new().fill(&mut send_buf[..]).unwrap();

    let mut recv_buf = vec![0; send_buf.len()];

    let req = [
        quiche::h3::Header::new(":method", "GET"),
        quiche::h3::Header::new(":scheme", "https"),
        quiche::h3::Header::new(":authority", "quic.tech"),
        quiche::h3::Header::new(":path", "/test"),
        quiche::h3::Header::new("user-agent", "quiche-test"),
    ];

    let resp = [
        quiche::h3::Header::new(":status", "200"),
        quiche::h3::Header::new("server", "quiche-test"),
    ];

    c.bench_function_over_inputs(
        "http3",
        move |b, &&size| {
            b.iter(|| {
                s.client
                    .send_request(&mut s.pipe.client, &req, true)
                    .unwrap();

                let mut recv_len = 0;

                while recv_len < size {
                    s.pipe.flush_client(&mut buf).unwrap();

                    match s.server.poll(&mut s.pipe.server) {
                        Ok((stream, quiche::h3::Event::Headers { .. })) => {
                            s.server
                                .send_response(
                                    &mut s.pipe.server,
                                    stream,
                                    &resp,
                                    false,
                                )
                                .unwrap();

                            s.server
                                .send_body(
                                    &mut s.pipe.server,
                                    stream,
                                    &send_buf[..size],
                                    true,
                                )
                                .unwrap();
                        },

                        _ => (),
                    }

                    s.pipe.flush_server(&mut buf).unwrap();

                    while let Ok(ev) = s.client.poll(&mut s.pipe.client) {
                        match ev {
                            (stream_id, quiche::h3::Event::Data) => {
                                let b = &mut recv_buf[recv_len..size];

                                if let Ok(r) = s.client.recv_body(
                                    &mut s.pipe.client,
                                    stream_id,
                                    b,
                                ) {
                                    recv_len += r;
                                }
                            },

                            _ => (),
                        };
                    }
                }

                assert_eq!(recv_len, size);
                assert_eq!(&recv_buf[..size], &send_buf[..size]);
            })
        },
        &[128_000, 256_000, 512_000, 1_000_000, 5_000_000],
    );
}

fn make_bench_config() -> quiche::Config {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
        .unwrap();
    config.set_max_packet_size(1350);
    config.set_initial_max_data(2u64.pow(62) - 1);
    config.set_initial_max_stream_data_bidi_local(2u64.pow(62) - 1);
    config.set_initial_max_stream_data_bidi_remote(2u64.pow(62) - 1);
    config.set_initial_max_stream_data_uni(150);
    config.set_initial_max_streams_bidi(2u64.pow(60) - 1);
    config.set_initial_max_streams_uni(5);
    config.verify_peer(false);

    config
}

criterion_group!(benches, handshake, stream, http3);

criterion_main!(benches);
