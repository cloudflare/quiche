#![no_main]

#[macro_use]
extern crate libfuzzer_sys;

use std::net::SocketAddr;

use std::sync::Mutex;
use std::sync::Once;
use std::sync::OnceLock;

static CONFIG: OnceLock<Mutex<quiche::Config>> = OnceLock::new();

static SCID: quiche::ConnectionId<'static> =
    quiche::ConnectionId::from_ref(&[0; quiche::MAX_CONN_ID_LEN]);

static LOG_INIT: Once = Once::new();

fuzz_target!(|data: &[u8]| {
    quiche_fuzz::reset_rand_for_fuzzing();

    let from: SocketAddr = "127.0.0.1:1234".parse().unwrap();
    let to: SocketAddr = "127.0.0.1:4321".parse().unwrap();

    LOG_INIT.call_once(|| env_logger::builder().format_timestamp_nanos().init());

    let mut buf = data.to_vec();

    let config = CONFIG.get_or_init(|| {
        let (crt_path, key_path) = quiche_fuzz::get_cert_path();

        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
        config.load_cert_chain_from_pem_file(&crt_path).unwrap();
        config.load_priv_key_from_pem_file(&key_path).unwrap();
        config
            .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
            .unwrap();
        config.set_initial_max_data(30);
        config.set_initial_max_stream_data_bidi_local(15);
        config.set_initial_max_stream_data_bidi_remote(15);
        config.set_initial_max_stream_data_uni(10);
        config.set_initial_max_streams_bidi(3);
        config.set_initial_max_streams_uni(3);

        config.discover_pmtu(true);
        config.enable_early_data();
        config.enable_hystart(true);

        Mutex::new(config)
    });

    let mut conn =
        quiche::accept(&SCID, None, to, from, &mut config.lock().unwrap())
            .unwrap();

    let info = quiche::RecvInfo { from, to };

    conn.recv(&mut buf, info).ok();

    let mut out_buf = [0; 1500];
    while conn.send(&mut out_buf).is_ok() {}
});
