fn main() -> Result<(), Box<dyn std::error::Error>> {
    // protox provides a pure-Rust proto compiler — no system protoc required.
    let fds = protox::compile(["proto/region.proto"], ["."])?;
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_fds(fds)?;
    Ok(())
}
