#![no_main]

#[macro_use]
extern crate libfuzzer_sys;

// Fuzzer for qpack codec. Checks that decode(encode(hdrs)) == hdrs. To get the
// initial hdrs, the fuzzer deserializes the input, and skips inputs where
// deserialization fails.
//
// The fuzzer could have been written to instead check encode(decode(input)) ==
// input. However, that transformation is not guaranteed to be the identify
// function, as there are multiple ways the same hdr list could be encoded.
fuzz_target!(|data: &[u8]| {
    let mut decoder = quiche::h3::qpack::Decoder::new();
    let mut encoder = quiche::h3::qpack::Encoder::new();
    let hdrs = match decoder.decode(&mut data.to_vec(), std::u64::MAX) {
        Err(_) => return,
        Ok(hdrs) => hdrs,
    };
    let mut encoded_hdrs = vec![0; data.len() * 10 + 1000];
    let encoded_size = encoder.encode(&hdrs, &mut encoded_hdrs).unwrap();

    let decoded_hdrs = decoder
        .decode(&mut encoded_hdrs[..encoded_size], std::u64::MAX)
        .unwrap();

    assert_eq!(hdrs, decoded_hdrs)
});
