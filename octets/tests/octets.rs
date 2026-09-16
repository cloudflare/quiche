// Copyright (C) 2026, Cloudflare, Inc.
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

use octets::Octets;
use octets::OctetsMut;

#[test]
fn get_u() {
    let d = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
    ];

    let mut b = Octets::with_slice(&d);
    assert_eq!(b.cap(), 18);
    assert_eq!(b.off(), 0);

    assert_eq!(b.get_u8().unwrap(), 1);
    assert_eq!(b.cap(), 17);
    assert_eq!(b.off(), 1);

    assert_eq!(b.get_u16().unwrap(), 0x203);
    assert_eq!(b.cap(), 15);
    assert_eq!(b.off(), 3);

    assert_eq!(b.get_u24().unwrap(), 0x40506);
    assert_eq!(b.cap(), 12);
    assert_eq!(b.off(), 6);

    assert_eq!(b.get_u32().unwrap(), 0x0708090a);
    assert_eq!(b.cap(), 8);
    assert_eq!(b.off(), 10);

    assert_eq!(b.get_u64().unwrap(), 0x0b0c0d0e0f101112);
    assert_eq!(b.cap(), 0);
    assert_eq!(b.off(), 18);

    assert!(b.get_u8().is_err());
    assert!(b.get_u16().is_err());
    assert!(b.get_u24().is_err());
    assert!(b.get_u32().is_err());
    assert!(b.get_u64().is_err());
}

#[test]
fn get_u_mut() {
    let mut d = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
    ];

    let mut b = OctetsMut::with_slice(&mut d);
    assert_eq!(b.cap(), 18);
    assert_eq!(b.off(), 0);

    assert_eq!(b.get_u8().unwrap(), 1);
    assert_eq!(b.cap(), 17);
    assert_eq!(b.off(), 1);

    assert_eq!(b.get_u16().unwrap(), 0x203);
    assert_eq!(b.cap(), 15);
    assert_eq!(b.off(), 3);

    assert_eq!(b.get_u24().unwrap(), 0x40506);
    assert_eq!(b.cap(), 12);
    assert_eq!(b.off(), 6);

    assert_eq!(b.get_u32().unwrap(), 0x0708090a);
    assert_eq!(b.cap(), 8);
    assert_eq!(b.off(), 10);

    assert_eq!(b.get_u64().unwrap(), 0x0b0c0d0e0f101112);
    assert_eq!(b.cap(), 0);
    assert_eq!(b.off(), 18);

    assert!(b.get_u8().is_err());
    assert!(b.get_u16().is_err());
    assert!(b.get_u24().is_err());
    assert!(b.get_u32().is_err());
    assert!(b.get_u64().is_err());
}

#[test]
fn peek_u() {
    let d = [1, 2];

    let mut b = Octets::with_slice(&d);
    assert_eq!(b.cap(), 2);
    assert_eq!(b.off(), 0);

    assert_eq!(b.peek_u8().unwrap(), 1);
    assert_eq!(b.cap(), 2);
    assert_eq!(b.off(), 0);

    assert_eq!(b.peek_u8().unwrap(), 1);
    assert_eq!(b.cap(), 2);
    assert_eq!(b.off(), 0);

    b.get_u16().unwrap();

    assert!(b.peek_u8().is_err());
}

#[test]
fn peek_u_mut() {
    let mut d = [1, 2];

    let mut b = OctetsMut::with_slice(&mut d);
    assert_eq!(b.cap(), 2);
    assert_eq!(b.off(), 0);

    assert_eq!(b.peek_u8().unwrap(), 1);
    assert_eq!(b.cap(), 2);
    assert_eq!(b.off(), 0);

    assert_eq!(b.peek_u8().unwrap(), 1);
    assert_eq!(b.cap(), 2);
    assert_eq!(b.off(), 0);

    b.get_u16().unwrap();

    assert!(b.peek_u8().is_err());
}

#[test]
fn get_bytes() {
    let d = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    let mut b = Octets::with_slice(&d);
    assert_eq!(b.cap(), 10);
    assert_eq!(b.off(), 0);

    assert_eq!(b.get_bytes(5).unwrap().as_ref(), [1, 2, 3, 4, 5]);
    assert_eq!(b.cap(), 5);
    assert_eq!(b.off(), 5);

    assert_eq!(b.get_bytes(3).unwrap().as_ref(), [6, 7, 8]);
    assert_eq!(b.cap(), 2);
    assert_eq!(b.off(), 8);

    assert!(b.get_bytes(3).is_err());
    assert_eq!(b.cap(), 2);
    assert_eq!(b.off(), 8);

    assert_eq!(b.get_bytes(2).unwrap().as_ref(), [9, 10]);
    assert_eq!(b.cap(), 0);
    assert_eq!(b.off(), 10);

    assert!(b.get_bytes(2).is_err());
}

#[test]
fn get_bytes_mut() {
    let mut d = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    let mut b = OctetsMut::with_slice(&mut d);
    assert_eq!(b.cap(), 10);
    assert_eq!(b.off(), 0);

    assert_eq!(b.get_bytes(5).unwrap().as_ref(), [1, 2, 3, 4, 5]);
    assert_eq!(b.cap(), 5);
    assert_eq!(b.off(), 5);

    assert_eq!(b.get_bytes(3).unwrap().as_ref(), [6, 7, 8]);
    assert_eq!(b.cap(), 2);
    assert_eq!(b.off(), 8);

    assert!(b.get_bytes(3).is_err());
    assert_eq!(b.cap(), 2);
    assert_eq!(b.off(), 8);

    assert_eq!(b.get_bytes(2).unwrap().as_ref(), [9, 10]);
    assert_eq!(b.cap(), 0);
    assert_eq!(b.off(), 10);

    assert!(b.get_bytes(2).is_err());
}

#[test]
fn peek_bytes() {
    let d = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    let mut b = Octets::with_slice(&d);
    assert_eq!(b.cap(), 10);
    assert_eq!(b.off(), 0);

    assert_eq!(b.peek_bytes(5).unwrap().as_ref(), [1, 2, 3, 4, 5]);
    assert_eq!(b.cap(), 10);
    assert_eq!(b.off(), 0);

    assert_eq!(b.peek_bytes(5).unwrap().as_ref(), [1, 2, 3, 4, 5]);
    assert_eq!(b.cap(), 10);
    assert_eq!(b.off(), 0);

    b.get_bytes(5).unwrap();
}

#[test]
fn peek_bytes_mut() {
    let mut d = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    let mut b = OctetsMut::with_slice(&mut d);
    assert_eq!(b.cap(), 10);
    assert_eq!(b.off(), 0);

    assert_eq!(b.peek_bytes(5).unwrap().as_ref(), [1, 2, 3, 4, 5]);
    assert_eq!(b.cap(), 10);
    assert_eq!(b.off(), 0);

    assert_eq!(b.peek_bytes(5).unwrap().as_ref(), [1, 2, 3, 4, 5]);
    assert_eq!(b.cap(), 10);
    assert_eq!(b.off(), 0);

    b.get_bytes(5).unwrap();
}

#[test]
fn get_varint() {
    let d = [0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c];
    let mut b = Octets::with_slice(&d);
    assert_eq!(b.get_varint().unwrap(), 151288809941952652);
    assert_eq!(b.cap(), 0);
    assert_eq!(b.off(), 8);

    let d = [0x9d, 0x7f, 0x3e, 0x7d];
    let mut b = Octets::with_slice(&d);
    assert_eq!(b.get_varint().unwrap(), 494878333);
    assert_eq!(b.cap(), 0);
    assert_eq!(b.off(), 4);

    let d = [0x7b, 0xbd];
    let mut b = Octets::with_slice(&d);
    assert_eq!(b.get_varint().unwrap(), 15293);
    assert_eq!(b.cap(), 0);
    assert_eq!(b.off(), 2);

    let d = [0x40, 0x25];
    let mut b = Octets::with_slice(&d);
    assert_eq!(b.get_varint().unwrap(), 37);
    assert_eq!(b.cap(), 0);
    assert_eq!(b.off(), 2);

    let d = [0x25];
    let mut b = Octets::with_slice(&d);
    assert_eq!(b.get_varint().unwrap(), 37);
    assert_eq!(b.cap(), 0);
    assert_eq!(b.off(), 1);
}

#[test]
fn get_varint_mut() {
    let mut d = [0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c];
    let mut b = OctetsMut::with_slice(&mut d);
    assert_eq!(b.get_varint().unwrap(), 151288809941952652);
    assert_eq!(b.cap(), 0);
    assert_eq!(b.off(), 8);

    let mut d = [0x9d, 0x7f, 0x3e, 0x7d];
    let mut b = OctetsMut::with_slice(&mut d);
    assert_eq!(b.get_varint().unwrap(), 494878333);
    assert_eq!(b.cap(), 0);
    assert_eq!(b.off(), 4);

    let mut d = [0x7b, 0xbd];
    let mut b = OctetsMut::with_slice(&mut d);
    assert_eq!(b.get_varint().unwrap(), 15293);
    assert_eq!(b.cap(), 0);
    assert_eq!(b.off(), 2);

    let mut d = [0x40, 0x25];
    let mut b = OctetsMut::with_slice(&mut d);
    assert_eq!(b.get_varint().unwrap(), 37);
    assert_eq!(b.cap(), 0);
    assert_eq!(b.off(), 2);

    let mut d = [0x25];
    let mut b = OctetsMut::with_slice(&mut d);
    assert_eq!(b.get_varint().unwrap(), 37);
    assert_eq!(b.cap(), 0);
    assert_eq!(b.off(), 1);
}

#[test]
fn put_varint() {
    let mut d = [0; 8];
    {
        let mut b = OctetsMut::with_slice(&mut d);
        assert!(b.put_varint(151288809941952652).is_ok());
        assert_eq!(b.cap(), 0);
        assert_eq!(b.off(), 8);
    }
    let exp = [0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c];
    assert_eq!(&d, &exp);

    let mut d = [0; 4];
    {
        let mut b = OctetsMut::with_slice(&mut d);
        assert!(b.put_varint(494878333).is_ok());
        assert_eq!(b.cap(), 0);
        assert_eq!(b.off(), 4);
    }
    let exp = [0x9d, 0x7f, 0x3e, 0x7d];
    assert_eq!(&d, &exp);

    let mut d = [0; 2];
    {
        let mut b = OctetsMut::with_slice(&mut d);
        assert!(b.put_varint(15293).is_ok());
        assert_eq!(b.cap(), 0);
        assert_eq!(b.off(), 2);
    }
    let exp = [0x7b, 0xbd];
    assert_eq!(&d, &exp);

    let mut d = [0; 1];
    {
        let mut b = OctetsMut::with_slice(&mut d);
        assert!(b.put_varint(37).is_ok());
        assert_eq!(b.cap(), 0);
        assert_eq!(b.off(), 1);
    }
    let exp = [0x25];
    assert_eq!(&d, &exp);

    let mut d = [0; 3];
    {
        let mut b = OctetsMut::with_slice(&mut d);
        assert!(b.put_varint(151288809941952652).is_err());
        assert_eq!(b.cap(), 3);
        assert_eq!(b.off(), 0);
    }
    let exp = [0; 3];
    assert_eq!(&d, &exp);
}

#[test]
#[should_panic]
fn varint_too_large() {
    let mut d = [0; 3];
    let mut b = OctetsMut::with_slice(&mut d);
    assert!(b.put_varint(u64::MAX).is_err());
}

#[test]
fn put_u() {
    let mut d = [0; 18];

    {
        let mut b = OctetsMut::with_slice(&mut d);
        assert_eq!(b.cap(), 18);
        assert_eq!(b.off(), 0);

        assert!(b.put_u8(1).is_ok());
        assert_eq!(b.cap(), 17);
        assert_eq!(b.off(), 1);

        assert!(b.put_u16(0x203).is_ok());
        assert_eq!(b.cap(), 15);
        assert_eq!(b.off(), 3);

        assert!(b.put_u24(0x40506).is_ok());
        assert_eq!(b.cap(), 12);
        assert_eq!(b.off(), 6);

        assert!(b.put_u32(0x0708090a).is_ok());
        assert_eq!(b.cap(), 8);
        assert_eq!(b.off(), 10);

        assert!(b.put_u64(0x0b0c0d0e0f101112).is_ok());
        assert_eq!(b.cap(), 0);
        assert_eq!(b.off(), 18);

        assert!(b.put_u8(1).is_err());
    }

    let exp = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
    ];
    assert_eq!(&d, &exp);
}

#[test]
fn put_bytes() {
    let mut d = [0; 5];

    {
        let mut b = OctetsMut::with_slice(&mut d);
        assert_eq!(b.cap(), 5);
        assert_eq!(b.off(), 0);

        let p = [0x0a, 0x0b, 0x0c, 0x0d, 0x0e];
        assert!(b.put_bytes(&p).is_ok());
        assert_eq!(b.cap(), 0);
        assert_eq!(b.off(), 5);

        assert!(b.put_u8(1).is_err());
    }

    let exp = [0xa, 0xb, 0xc, 0xd, 0xe];
    assert_eq!(&d, &exp);
}

#[test]
fn rewind() {
    let d = [0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c];
    let mut b = Octets::with_slice(&d);
    assert_eq!(b.get_varint().unwrap(), 151288809941952652);
    assert_eq!(b.cap(), 0);
    assert_eq!(b.off(), 8);

    assert_eq!(b.rewind(4), Ok(()));
    assert_eq!(b.cap(), 4);
    assert_eq!(b.off(), 4);

    assert_eq!(b.get_u8().unwrap(), 0xff);
    assert_eq!(b.cap(), 3);
    assert_eq!(b.off(), 5);

    assert!(b.rewind(6).is_err());

    assert_eq!(b.rewind(5), Ok(()));
    assert_eq!(b.cap(), 8);
    assert_eq!(b.off(), 0);

    assert!(b.rewind(1).is_err());
}

#[test]
fn rewind_mut() {
    let mut d = [0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c];
    let mut b = OctetsMut::with_slice(&mut d);
    assert_eq!(b.get_varint().unwrap(), 151288809941952652);
    assert_eq!(b.cap(), 0);
    assert_eq!(b.off(), 8);

    assert_eq!(b.rewind(4), Ok(()));
    assert_eq!(b.cap(), 4);
    assert_eq!(b.off(), 4);

    assert_eq!(b.get_u8().unwrap(), 0xff);
    assert_eq!(b.cap(), 3);
    assert_eq!(b.off(), 5);

    assert!(b.rewind(6).is_err());

    assert_eq!(b.rewind(5), Ok(()));
    assert_eq!(b.cap(), 8);
    assert_eq!(b.off(), 0);

    assert!(b.rewind(1).is_err());
}

#[test]
fn split() {
    let mut d = b"helloworld".to_vec();

    let mut b = OctetsMut::with_slice(&mut d);
    assert_eq!(b.cap(), 10);
    assert_eq!(b.off(), 0);
    assert_eq!(b.as_ref(), b"helloworld");

    assert!(b.get_bytes(5).is_ok());
    assert_eq!(b.cap(), 5);
    assert_eq!(b.off(), 5);
    assert_eq!(b.as_ref(), b"world");

    let off = b.off();

    let (first, last) = b.split_at(off).unwrap();
    assert_eq!(first.cap(), 5);
    assert_eq!(first.off(), 0);
    assert_eq!(first.as_ref(), b"hello");

    assert_eq!(last.cap(), 5);
    assert_eq!(last.off(), 0);
    assert_eq!(last.as_ref(), b"world");
}

#[test]
fn split_at() {
    let mut d = b"helloworld".to_vec();

    {
        let mut b = OctetsMut::with_slice(&mut d);
        let (first, second) = b.split_at(5).unwrap();

        let mut exp1 = b"hello".to_vec();
        assert_eq!(first.as_ref(), &mut exp1[..]);

        let mut exp2 = b"world".to_vec();
        assert_eq!(second.as_ref(), &mut exp2[..]);
    }

    {
        let mut b = OctetsMut::with_slice(&mut d);
        let (first, second) = b.split_at(10).unwrap();

        let mut exp1 = b"helloworld".to_vec();
        assert_eq!(first.as_ref(), &mut exp1[..]);

        let mut exp2 = b"".to_vec();
        assert_eq!(second.as_ref(), &mut exp2[..]);
    }

    {
        let mut b = OctetsMut::with_slice(&mut d);
        let (first, second) = b.split_at(9).unwrap();

        let mut exp1 = b"helloworl".to_vec();
        assert_eq!(first.as_ref(), &mut exp1[..]);

        let mut exp2 = b"d".to_vec();
        assert_eq!(second.as_ref(), &mut exp2[..]);
    }

    {
        let mut b = OctetsMut::with_slice(&mut d);
        assert!(b.split_at(11).is_err());
    }
}

#[test]
fn slice() {
    let d = b"helloworld".to_vec();

    {
        let b = Octets::with_slice(&d);
        let exp = b"hello".to_vec();
        assert_eq!(b.slice(5), Ok(&exp[..]));
    }

    {
        let b = Octets::with_slice(&d);
        let exp = b"".to_vec();
        assert_eq!(b.slice(0), Ok(&exp[..]));
    }

    {
        let mut b = Octets::with_slice(&d);
        b.get_bytes(5).unwrap();

        let exp = b"world".to_vec();
        assert_eq!(b.slice(5), Ok(&exp[..]));
    }

    {
        let b = Octets::with_slice(&d);
        assert!(b.slice(11).is_err());
    }
}

#[test]
fn slice_mut() {
    let mut d = b"helloworld".to_vec();

    {
        let mut b = OctetsMut::with_slice(&mut d);
        let mut exp = b"hello".to_vec();
        assert_eq!(b.slice(5), Ok(&mut exp[..]));
    }

    {
        let mut b = OctetsMut::with_slice(&mut d);
        let mut exp = b"".to_vec();
        assert_eq!(b.slice(0), Ok(&mut exp[..]));
    }

    {
        let mut b = OctetsMut::with_slice(&mut d);
        b.get_bytes(5).unwrap();

        let mut exp = b"world".to_vec();
        assert_eq!(b.slice(5), Ok(&mut exp[..]));
    }

    {
        let mut b = OctetsMut::with_slice(&mut d);
        assert!(b.slice(11).is_err());
    }
}

#[test]
fn slice_last() {
    let d = b"helloworld".to_vec();

    {
        let b = Octets::with_slice(&d);
        let exp = b"orld".to_vec();
        assert_eq!(b.slice_last(4), Ok(&exp[..]));
    }

    {
        let mut b = Octets::with_slice(&d);
        b.get_bytes(5).unwrap();
        let exp = b"orld".to_vec();
        assert_eq!(b.slice_last(4), Ok(&exp[..]));
    }

    {
        let b = Octets::with_slice(&d);
        let exp = b"d".to_vec();
        assert_eq!(b.slice_last(1), Ok(&exp[..]));
    }

    {
        let b = Octets::with_slice(&d);
        let exp = b"".to_vec();
        assert_eq!(b.slice_last(0), Ok(&exp[..]));
    }

    {
        let b = Octets::with_slice(&d);
        let exp = b"helloworld".to_vec();
        assert_eq!(b.slice_last(10), Ok(&exp[..]));
    }

    {
        let b = Octets::with_slice(&d);
        assert!(b.slice_last(11).is_err());
    }
}

#[test]
fn slice_last_mut() {
    let mut d = b"helloworld".to_vec();

    {
        let mut b = OctetsMut::with_slice(&mut d);
        let mut exp = b"orld".to_vec();
        assert_eq!(b.slice_last(4), Ok(&mut exp[..]));
    }

    {
        let mut b = OctetsMut::with_slice(&mut d);
        b.get_bytes(5).unwrap();
        let mut exp = b"orld".to_vec();
        assert_eq!(b.slice_last(4), Ok(&mut exp[..]));
    }

    {
        let mut b = OctetsMut::with_slice(&mut d);
        let mut exp = b"d".to_vec();
        assert_eq!(b.slice_last(1), Ok(&mut exp[..]));
    }

    {
        let mut b = OctetsMut::with_slice(&mut d);
        let mut exp = b"".to_vec();
        assert_eq!(b.slice_last(0), Ok(&mut exp[..]));
    }

    {
        let mut b = OctetsMut::with_slice(&mut d);
        let mut exp = b"helloworld".to_vec();
        assert_eq!(b.slice_last(10), Ok(&mut exp[..]));
    }

    {
        let mut b = OctetsMut::with_slice(&mut d);
        assert!(b.slice_last(11).is_err());
    }
}
