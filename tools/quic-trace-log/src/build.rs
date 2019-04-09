use protoc_rust::Customize;

fn main() {
    protoc_rust::run(protoc_rust::Args {
        out_dir: "src/",
        input: &["quic_trace.proto"],
        includes: &["."],
        customize: Customize {
            ..Default::default()
        },
    })
    .expect("protoc");
}
