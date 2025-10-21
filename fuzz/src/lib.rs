use quiche::h3::NameValue;

pub struct PktsData<'a> {
    pub data: &'a [u8],
}

pub struct PktIterator<'a> {
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

pub fn server_process(
    pkt: &[u8], conn: &mut quiche::Connection,
    h3_conn: &mut Option<quiche::h3::Connection>, info: quiche::RecvInfo,
) {
    let mut buf = pkt.to_vec();
    conn.recv(&mut buf, info).ok();

    if (conn.is_in_early_data() || conn.is_established()) && h3_conn.is_none() {
        let h3_config = quiche::h3::Config::new().unwrap();

        if let Ok(c) = quiche::h3::Connection::with_transport(conn, &h3_config) {
            *h3_conn = Some(c);
        }
    }

    if h3_conn.is_some() {
        let h3c = h3_conn.as_mut().unwrap();
        loop {
            let r = h3c.poll(conn);

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
