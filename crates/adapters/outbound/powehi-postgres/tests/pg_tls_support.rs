//! Regression for #243: sqlx must be built with TLS, because RDS runs `rds.force_ssl=1`.
//!
//! A stub server answers the `SSLRequest` with `N` (no TLS). With TLS compiled in, sqlx
//! reports the *server* refused; without it, sqlx fails with "built without TLS support"
//! before ever negotiating.

use std::str::FromStr;

use sqlx::{
    postgres::{PgConnectOptions, PgSslMode},
    ConnectOptions,
};
use tokio::{io::AsyncWriteExt, net::TcpListener};

#[tokio::test]
async fn sslmode_verify_full_negotiates_tls_instead_of_failing_unbuilt() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.expect("accept");
        // Read the 8-byte SSLRequest, refuse TLS.
        let mut req = [0u8; 8];
        tokio::io::AsyncReadExt::read_exact(&mut sock, &mut req)
            .await
            .expect("sslrequest");
        sock.write_all(b"N").await.expect("reply");
    });

    let opts = PgConnectOptions::from_str(&format!(
        "postgres://u:p@127.0.0.1:{port}/db?sslmode=verify-full&sslrootcert=/nonexistent.pem"
    ))
    .expect("url parses");
    let err = opts
        .connect()
        .await
        .expect_err("stub refuses TLS")
        .to_string();
    assert!(
        !err.contains("built without TLS"),
        "sqlx lacks a TLS backend: {err}"
    );
}

#[test]
fn verify_full_mode_parses() {
    let opts = PgConnectOptions::from_str("postgres://u:p@h/db?sslmode=verify-full").expect("ok");
    assert!(matches!(opts.get_ssl_mode(), PgSslMode::VerifyFull));
}
