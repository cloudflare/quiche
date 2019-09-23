#![no_main]

#[macro_use]
extern crate libfuzzer_sys;

fuzz_target!(|data: &[u8]| {
    let mut buf = data.to_vec();
    let mut decoder = quiche::h3::qpack::Decoder::new();

    decoder.decode(&mut buf, std::u64::MAX).ok();
});
