use foundations::telemetry::log;
use tokio_quiche::args::*;
use tokio_quiche::http3::driver::ClientH3Event;
use tokio_quiche::http3::driver::H3Event;
use tokio_quiche::http3::driver::InboundFrame;
use tokio_quiche::http3::driver::IncomingH3Headers;
use tokio_quiche::quiche::h3;

#[tokio::main]
async fn main() -> tokio_quiche::QuicResult<()> {
    let docopt = docopt::Docopt::new(CLIENT_USAGE).unwrap();
    let args = ClientArgs::with_docopt(&docopt);
    // We'll only connect to the first server provided in URL list.
    let connect_url = &args.urls[0];

    // Resolve server address.
    let peer_addr = if let Some(addr) = &args.connect_to {
        addr.parse().expect("--connect-to is expected to be a string containing an IPv4 or IPv6 address with a port. E.g. 192.0.2.0:443")
    } else {
        *connect_url.socket_addrs(|| None).unwrap().first().unwrap()
    };

    let bind_addr = match peer_addr {
        std::net::SocketAddr::V4(_) => format!("0.0.0.0:{}", args.source_port),
        std::net::SocketAddr::V6(_) => format!("[::]:{}", args.source_port),
    };
    let bind_to: String = bind_addr.parse().unwrap();
    let socket = tokio::net::UdpSocket::bind(bind_to).await?;
    let file = &args.urls[0].path().to_string();
    println!("Connect url: {:}", peer_addr);
    println!("Args method: {}", &args.method);
    println!("Args method: {:?}", &args.dump_response_path);
    socket.connect(peer_addr).await?;

    let (_, mut controller) = tokio_quiche::quic::connect(socket, None).await?;

    println!("Path is: {:?}", file);

    let request = tokio_quiche::http3::driver::NewClientRequest {
        request_id: 0,
        headers: vec![
            h3::Header::new(b":method", b"GET"),
            h3::Header::new(b":path", b"README.md"),
        ],
        body_writer: None,
    };
    controller.request_sender().send(request).unwrap();

    while let Some(event) = controller.event_receiver_mut().recv().await {
        match event {
            ClientH3Event::Core(H3Event::IncomingHeaders(
                IncomingH3Headers {
                    stream_id,
                    headers,
                    mut recv,
                    ..
                },
            )) => {
                log::info!("incomming headers"; "stream_id" => stream_id, "headers" => ?headers);
                'body: while let Some(frame) = recv.recv().await {
                    match frame {
                        InboundFrame::Body(pooled, fin) => {
                            log::info!("inbound body: {:?}", std::str::from_utf8(&pooled);
                                "fin" => fin,
                                "len" => pooled.len()
                            );
                            println!("{}", std::str::from_utf8(&pooled).unwrap());

                            if fin {
                                println!("received full body, exiting");
                                break 'body;
                            }
                        },
                        InboundFrame::Datagram(pooled) => {
                            log::info!("inbound datagram"; "len" => pooled.len());
                        },
                    }
                }
            },
            ClientH3Event::Core(H3Event::BodyBytesReceived {
                fin: true, ..
            }) => {
                println!("fin received");
                break;
            },
            ClientH3Event::Core(event) => println!("received event: {event:?}"),
            ClientH3Event::NewOutboundRequest {
                stream_id,
                request_id,
            } => log::info!(
                "sending outbound request";
                "stream_id" => stream_id,
                "request_id" => request_id
            ),
        }
    }
    Ok(())
}
