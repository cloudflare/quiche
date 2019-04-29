// Copyright (C) 2018, Cloudflare, Inc.
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

    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(b"\x06proto1\x06proto2")
        .unwrap();
    config.set_initial_max_data(2u64.pow(62) - 1);
    config.set_initial_max_stream_data_bidi_local(2u64.pow(62) - 1);
    config.set_initial_max_stream_data_bidi_remote(2u64.pow(62) - 1);
    config.set_initial_max_streams_bidi(3);
    config.set_initial_max_streams_uni(3);
    config.verify_peer(false);

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

    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(b"\x06proto1\x06proto2")
        .unwrap();
    config.set_max_packet_size(1350);
    config.set_initial_max_data(2u64.pow(62) - 1);
    config.set_initial_max_stream_data_bidi_local(2u64.pow(62) - 1);
    config.set_initial_max_stream_data_bidi_remote(2u64.pow(62) - 1);
    config.set_initial_max_streams_bidi(3);
    config.set_initial_max_streams_uni(3);
    config.verify_peer(false);

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
                    loop {
                        let len = match pipe.client.send(&mut buf) {
                            Ok(write) => write,

                            Err(quiche::Error::Done) => break,

                            Err(e) => panic!("client send failed {}", e),
                        };

                        match pipe.server.recv(&mut buf[..len]) {
                            Ok(_) => (),

                            Err(quiche::Error::Done) => (),

                            Err(e) => panic!("server recv failed {}", e),
                        }
                    }

                    let (len, _) = pipe
                        .server
                        .stream_recv(4, &mut recv_buf[recv_len..])
                        .unwrap();
                    recv_len += len;

                    loop {
                        let len = match pipe.server.send(&mut buf) {
                            Ok(write) => write,

                            Err(quiche::Error::Done) => break,

                            Err(e) => panic!("server send failed {}", e),
                        };

                        match pipe.client.recv(&mut buf[..len]) {
                            Ok(_) => (),

                            Err(quiche::Error::Done) => (),

                            Err(e) => panic!("client recv failed {}", e),
                        }
                    }
                }

                assert_eq!(&recv_buf[..size], &send_buf[..size]);
            })
        },
        &[128_000, 5_000_000],
    );
}

criterion_group!(benches, handshake, stream);

criterion_main!(benches);
