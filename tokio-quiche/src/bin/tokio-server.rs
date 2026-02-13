use futures::SinkExt as _;
use futures::StreamExt as _;
use quiche::h3::NameValue;
use quiche::h3::Priority;
use std::str::from_utf8;
use tokio_quiche::args::*;
use tokio_quiche::buf_factory::BufFactory;
use tokio_quiche::http3::driver::H3Event;
use tokio_quiche::http3::driver::IncomingH3Headers;
use tokio_quiche::http3::driver::OutboundFrame;
use tokio_quiche::http3::settings::Http3Settings;
use tokio_quiche::listen;
use tokio_quiche::metrics::DefaultMetrics;
use tokio_quiche::quiche::h3;
use tokio_quiche::settings::QuicSettings;
use tokio_quiche::ConnectionParams;
use tokio_quiche::ServerH3Controller;
use tokio_quiche::ServerH3Driver;

#[tokio::main]
async fn main() -> tokio_quiche::QuicResult<()> {
    let docopt: docopt::Docopt = docopt::Docopt::new(SERVER_USAGE).unwrap();
    let args = ServerArgs::with_docopt(&docopt);

    let bind_to: String = args.listen.parse().unwrap();

    let socket = tokio::net::UdpSocket::bind(bind_to).await?;
    let settings = QuicSettings::default();

    let mut listeners = listen(
        [socket],
        ConnectionParams::new_server(
            settings,
            tokio_quiche::settings::TlsCertificatePaths {
                cert: &args.cert,
                private_key: &args.key,
                kind: tokio_quiche::settings::CertificateKind::X509,
            },
            Default::default(),
        ),
        DefaultMetrics,
    )?;

    let accept_stream = &mut listeners[0];

    while let Some(conn) = accept_stream.next().await {
        let (driver, controller) = ServerH3Driver::new(Http3Settings::default());
        conn?.start(driver);
        tokio::spawn(handle_connection(controller));
    }

    Ok(())
}

async fn handle_connection(mut controller: ServerH3Controller) {
    loop {
        match controller.event_receiver_mut().recv().await {
            Some(event) => {
                match event {
                    tokio_quiche::http3::driver::ServerH3Event::Core(
                        H3Event::IncomingHeaders(IncomingH3Headers { .. }),
                    ) => {},
                    tokio_quiche::http3::driver::ServerH3Event::Headers {
                        mut incoming_headers,
                        ..
                    } => {
                        incoming_headers
                            .send
                            .send(OutboundFrame::Headers(
                                vec![h3::Header::new(b":status", b"200")],
                                Some(Priority::new(0, true)),
                            ))
                            .await
                            .unwrap();
                        let request = &incoming_headers.headers;
                        for hdr in request {
                            match hdr.name() {
                                b":path" => {
                                    let path =
                                        Some(from_utf8(hdr.value()).unwrap());
                                    println!("Path is: {:?}", path);
                                    let body = std::fs::read(path.unwrap())
                                        .unwrap_or_else(|_| {
                                            b"Not Found!\r\n".to_vec()
                                        });
                                    incoming_headers
                                        .send
                                        .send(OutboundFrame::body(
                                            BufFactory::buf_from_slice(&body),
                                            true,
                                        ))
                                        .await
                                        .unwrap();
                                },
                                b":method" => {
                                    assert_eq!(
                                        from_utf8(hdr.value()).unwrap(),
                                        "GET"
                                    )
                                },
                                b":scheme" => {
                                    assert_eq!(
                                        from_utf8(hdr.value()).unwrap(),
                                        "http"
                                    )
                                },
                                b":authority" => {
                                    // TODO
                                },
                                b"user-agent" => {
                                    // ignore
                                },
                                b => {
                                    println!(
                                        "{} header not supported",
                                        from_utf8(b).unwrap()
                                    );
                                },
                            }
                        }
                    },
                    event => {
                        println!("event: {event:?}");
                    },
                }
            },
            None => (),
        }
    }
}
