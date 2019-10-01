#![no_main]

#[macro_use]
extern crate libfuzzer_sys;

#[macro_use]
extern crate lazy_static;

use std::sync::Mutex;

lazy_static! {
    static ref CONFIG: Mutex<quiche::Config> = {
        let crt_path = std::env::var("QUICHE_FUZZ_CRT")
            .unwrap_or_else(|_| "examples/cert.crt".to_string());
        let key_path = std::env::var("QUICHE_FUZZ_KEY")
            .unwrap_or_else(|_| "examples/cert.key".to_string());

        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
        config.load_cert_chain_from_pem_file(&crt_path).unwrap();
        config.load_priv_key_from_pem_file(&key_path).unwrap();
        config
            .set_application_protos(b"\x05hq-23\x08http/0.9")
            .unwrap();
        config.set_initial_max_data(30);
        config.set_initial_max_stream_data_bidi_local(15);
        config.set_initial_max_stream_data_bidi_remote(15);
        config.set_initial_max_stream_data_uni(10);
        config.set_initial_max_streams_bidi(3);
        config.set_initial_max_streams_uni(3);

        Mutex::new(config)
    };
}

static SCID: [u8; quiche::MAX_CONN_ID_LEN] = [0; quiche::MAX_CONN_ID_LEN];

fuzz_target!(|data: &[u8]| {
    let mut buf = data.to_vec();
    let mut conn =
        quiche::accept(&SCID, None, &mut CONFIG.lock().unwrap()).unwrap();

    conn.recv(&mut buf).ok();
});
