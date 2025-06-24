#![no_main]

#[macro_use]
extern crate libfuzzer_sys;

use std::net::SocketAddr;

use std::sync::Mutex;
use std::sync::Once;
use std::sync::OnceLock;

use quiche::h3::NameValue;

static CONFIG: OnceLock<Mutex<quiche::Config>> = OnceLock::new();

static SCID: quiche::ConnectionId<'static> =
    quiche::ConnectionId::from_ref(&[0; quiche::MAX_CONN_ID_LEN]);

static LOG_INIT: Once = Once::new();

struct PktsData<'a> {
    data: &'a [u8],
}

struct PktIterator<'a> {
    data: &'a [u8],
    index: usize,
}

impl<'a> Iterator for PktIterator<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.data.len() {
            let start = self.index;
            if self.index + 4 <= self.data.len() {
                for i in self.index..self.data.len() - 4 {
                    if &self.data[i..i + 4] == b"fuzz" {
                        self.index = i + 4;
                        return Some(&self.data[start..i]);
                    }
                }
            }
            self.index = self.data.len();
            Some(&self.data[start..])
        } else {
            None
        }
    }
}

impl<'a> PktsData<'a> {
    pub fn iter(&self) -> PktIterator<'_> {
        PktIterator {
            data: self.data,
            index: 0,
        }
    }
}

extern "C" {
    fn RAND_reset_for_fuzzing();
}

fuzz_target!(|data: &[u8]| {
    unsafe {
        RAND_reset_for_fuzzing();
    }
    let from: SocketAddr = "127.0.0.1:1234".parse().unwrap();
    let to: SocketAddr = "127.0.0.1:4321".parse().unwrap();

    LOG_INIT.call_once(|| env_logger::builder().format_timestamp_nanos().init());

    let packets = PktsData { data };

    let config = CONFIG.get_or_init(|| {
        let crt_path = std::env::var("QUICHE_FUZZ_CRT")
            .unwrap_or_else(|_| "fuzz/cert.crt".to_string());
        let key_path = std::env::var("QUICHE_FUZZ_KEY")
            .unwrap_or_else(|_| "fuzz/cert.key".to_string());

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

    let mut connc = quiche::connect(
        Some("quic.tech"),
        &SCID,
        from,
        to,
        &mut config.lock().unwrap(),
    )
    .unwrap();

    let info = quiche::RecvInfo { from, to };

    while !conn.is_established() || !connc.is_established() {
        let flight = quiche::test_utils::emit_flight(&mut connc).unwrap();
        quiche::test_utils::process_flight(&mut conn, flight).unwrap();

        let flight = quiche::test_utils::emit_flight(&mut conn).unwrap();
        quiche::test_utils::process_flight(&mut connc, flight).unwrap();
    }
    let h3_config = quiche::h3::Config::new().unwrap();
    let mut h3_conn = None;
    for pkt in packets.iter() {
        let mut buf = pkt.to_vec();
        conn.recv(&mut buf, info).ok();
        if (conn.is_in_early_data() || conn.is_established()) && h3_conn.is_none()
        {
            h3_conn = Some(
                quiche::h3::Connection::with_transport(&mut conn, &h3_config)
                    .unwrap(),
            );
        }
        if h3_conn.is_some() {
            let h3c = h3_conn.as_mut().unwrap();
            // for stream_id in conn.writable() {}
            loop {
                let r = h3c.poll(&mut conn);
                match r {
                    Ok((
                        _stream_id,
                        quiche::h3::Event::Headers {
                            list,
                            more_frames: _,
                        },
                    )) => {
                        let mut headers = list.into_iter();
                        // Look for the request's method.
                        let method = headers.find(|h| h.name() == b":method");
                        if method.is_none() {
                            break;
                        }
                        let method = method.unwrap();
                        // Look for the request's path.
                        let path = headers.find(|h| h.name() == b":path");
                        if path.is_none() {
                            break;
                        }
                        let path = path.unwrap();
                        if method.value() == b"GET" && path.value() == b"/" {
                            let _resp = vec![
                                quiche::h3::Header::new(
                                    b":status",
                                    200.to_string().as_bytes(),
                                ),
                                quiche::h3::Header::new(b"server", b"quiche"),
                            ];
                        }
                    },

                    Ok((_stream_id, quiche::h3::Event::Data)) => {},

                    Ok((_stream_id, quiche::h3::Event::Finished)) => {},

                    Ok((_stream_id, quiche::h3::Event::Reset(_err))) => {},

                    Ok((_flow_id, quiche::h3::Event::PriorityUpdate)) => {},

                    Ok((_goaway_id, quiche::h3::Event::GoAway)) => {
                        // Peer signalled it is going away, handle it.
                    },

                    Err(quiche::h3::Error::Done) => {
                        // Done reading.
                        break;
                    },

                    Err(_e) => {
                        // An error occurred, handle it.
                        break;
                    },
                }
            }
        }
        let mut out_buf = [0; 1500];
        while conn.send(&mut out_buf).is_ok() {}
    }
});
