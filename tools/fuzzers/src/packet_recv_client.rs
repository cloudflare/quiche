#[macro_use]
extern crate honggfuzz;

fn main() {
    loop {
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
        config
            .set_application_protos(b"\x06proto1\x06proto2")
            .unwrap();
        config.set_initial_max_data(30);
        config.set_initial_max_stream_data_bidi_local(15);
        config.set_initial_max_stream_data_bidi_remote(15);
        config.set_initial_max_stream_data_uni(10);
        config.set_initial_max_streams_bidi(3);
        config.set_initial_max_streams_uni(3);
        config.verify_peer(false);

        let client_scid = [0; 16];

        fuzz!(|data: &[u8]| {
            let mut buf = data.to_vec();
            let mut conn =
                quiche::connect(Some("quic.tech"), &client_scid, &mut config)
                    .unwrap();

            conn.recv(&mut buf).ok();
        });
    }
}
