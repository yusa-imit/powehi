use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};

use super::*;

struct Chain {
    ca: CertificateDer<'static>,
    leaf: CertificateDer<'static>,
    leaf_key: Vec<u8>,
}

/// A CA and a `localhost` leaf it signed.
fn chain() -> Chain {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(vec![]).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let leaf_key = KeyPair::generate().unwrap();
    let leaf_params = CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
    let leaf = leaf_params.signed_by(&leaf_key, &ca, &ca_key).unwrap();
    Chain {
        ca: ca.der().clone(),
        leaf: leaf.der().clone(),
        leaf_key: leaf_key.serialize_der(),
    }
}

fn verifier(chain: &Chain, pins: &[[u8; PIN_LEN]]) -> PinnedVerifier {
    let mut roots = RootCertStore::empty();
    roots.add(chain.ca.clone()).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    PinnedVerifier {
        inner: WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
            .build()
            .unwrap(),
        pins: PinSet::new(pins).unwrap(),
        provider,
    }
}

fn check(v: &PinnedVerifier, chain: &Chain, name: &'static str) -> Result<(), Error> {
    let name = ServerName::try_from(name).unwrap();
    v.verify_server_cert(&chain.leaf, &[], &name, &[], UnixTime::now())
        .map(|_| ())
}

const OTHER_A: [u8; PIN_LEN] = [0xA1; PIN_LEN];
const OTHER_B: [u8; PIN_LEN] = [0xB2; PIN_LEN];

#[test]
fn pinned_leaf_key_is_accepted() {
    let c = chain();
    let v = verifier(&c, &[spki_pin(&c.leaf).unwrap(), OTHER_A]);
    assert!(check(&v, &c, "localhost").is_ok());
}

#[test]
fn backup_pin_alone_is_enough() {
    let c = chain();
    let v = verifier(&c, &[OTHER_A, spki_pin(&c.leaf).unwrap()]);
    assert!(check(&v, &c, "localhost").is_ok());
}

#[test]
fn valid_but_unpinned_certificate_is_rejected() {
    let c = chain();
    let v = verifier(&c, &[OTHER_A, OTHER_B]);
    let err = check(&v, &c, "localhost").unwrap_err();
    assert!(matches!(
        err,
        Error::InvalidCertificate(CertificateError::Other(_))
    ));
}

#[test]
fn pinned_issuer_in_the_chain_is_accepted() {
    let c = chain();
    let v = verifier(&c, &[spki_pin(&c.ca).unwrap(), OTHER_A]);
    let name = ServerName::try_from("localhost").unwrap();
    let res = v.verify_server_cert(
        &c.leaf,
        std::slice::from_ref(&c.ca),
        &name,
        &[],
        UnixTime::now(),
    );
    assert!(res.is_ok());
}

#[test]
fn matching_pin_does_not_bypass_webpki() {
    let c = chain();
    let v = verifier(&c, &[spki_pin(&c.leaf).unwrap(), OTHER_A]);
    // Wrong name: WebPKI fails first even though the key is pinned.
    let err = check(&v, &c, "example.org").unwrap_err();
    assert!(!matches!(
        err,
        Error::InvalidCertificate(CertificateError::Other(_))
    ));
    // Untrusted issuer: a pinned leaf from another CA is still rejected.
    let stranger = chain();
    let v = verifier(&stranger, &[spki_pin(&c.leaf).unwrap(), OTHER_A]);
    assert!(check(&v, &c, "localhost").is_err());
}

#[test]
fn pin_set_validation() {
    assert_eq!(PinSet::new(&[]), Err(PinError::TooFew(0)));
    assert_eq!(PinSet::new(&[OTHER_A]), Err(PinError::TooFew(1)));
    assert_eq!(PinSet::new(&[OTHER_A, OTHER_A]), Err(PinError::Duplicate));
    let many: Vec<[u8; PIN_LEN]> = (0..=MAX_PINS as u8).map(|i| [i; PIN_LEN]).collect();
    assert_eq!(PinSet::new(&many), Err(PinError::TooMany(MAX_PINS + 1)));
    assert!(PinSet::new(&[OTHER_A, OTHER_B]).is_ok());
}

#[test]
fn production_pins_are_empty_or_a_valid_set() {
    assert!(PinPolicy::production().is_ok());
    if PRODUCTION_PINS.is_empty() {
        assert_eq!(PinPolicy::production().unwrap(), PinPolicy::WebPkiOnly);
    }
}

#[test]
fn garbage_certificate_has_no_pin() {
    assert_eq!(spki_pin(&CertificateDer::from(vec![1u8, 2, 3])), None);
}

#[test]
fn configs_build_for_both_policies() {
    let set = PinSet::new(&[OTHER_A, OTHER_B]).unwrap();
    for policy in [PinPolicy::WebPkiOnly, PinPolicy::Enforce(set)] {
        assert!(tls_config(webpki_roots_store(), &policy).is_ok());
    }
}

/// Serves one TLS 1.3 connection with `chain`'s leaf, answering any request with `200 ok`.
async fn tls_server(chain: &Chain) -> u16 {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let key = rustls::pki_types::PrivateKeyDer::try_from(chain.leaf_key.clone()).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![chain.leaf.clone()], key)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (sock, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(sock).await else {
                    return;
                };
                let mut buf = [0u8; 1024];
                let _ = tls.read(&mut buf).await;
                let resp = b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok";
                let _ = tls.write_all(resp).await;
                let _ = tls.shutdown().await;
            });
        }
    });
    port
}

#[tokio::test]
async fn http_client_enforces_pins_end_to_end() {
    let c = chain();
    let port = tls_server(&c).await;
    let url = format!("https://localhost:{port}/");
    let roots = || {
        let mut r = RootCertStore::empty();
        r.add(c.ca.clone()).unwrap();
        r
    };
    let pinned = PinPolicy::Enforce(PinSet::new(&[spki_pin(&c.leaf).unwrap(), OTHER_A]).unwrap());
    let client = crate::status::http_client_with(roots(), &pinned).unwrap();
    assert_eq!(
        client.get(&url).send().await.unwrap().text().await.unwrap(),
        "ok"
    );

    let wrong = PinPolicy::Enforce(PinSet::new(&[OTHER_A, OTHER_B]).unwrap());
    let client = crate::status::http_client_with(roots(), &wrong).unwrap();
    assert!(client.get(&url).send().await.is_err());

    let client = crate::status::http_client_with(roots(), &PinPolicy::WebPkiOnly).unwrap();
    assert!(client.get(&url).send().await.is_ok());
}

/// A CA with its own DN, so two CAs are distinguishable.
fn named_ca(name: &str) -> (rcgen::Certificate, KeyPair) {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec![]).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    (params.self_signed(&key).unwrap(), key)
}

#[test]
fn appended_genuine_issuer_does_not_satisfy_a_pin_for_a_rogue_path() {
    let (genuine, _) = named_ca("genuine");
    let (rogue, rogue_key) = named_ca("rogue");
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec!["localhost".to_owned()])
        .unwrap()
        .signed_by(&leaf_key, &rogue, &rogue_key)
        .unwrap();
    // The client trusts both CAs; only the genuine one is pinned.
    let mut roots = RootCertStore::empty();
    roots.add(genuine.der().clone()).unwrap();
    roots.add(rogue.der().clone()).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let v = PinnedVerifier {
        inner: WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
            .build()
            .unwrap(),
        pins: PinSet::new(&[spki_pin(genuine.der()).unwrap(), OTHER_A]).unwrap(),
        provider,
    };
    let name = ServerName::try_from("localhost").unwrap();
    let res = v.verify_server_cert(
        leaf.der(),
        std::slice::from_ref(genuine.der()),
        &name,
        &[],
        UnixTime::now(),
    );
    assert!(res.is_err());
}

#[test]
fn pin_is_sha256_of_the_der_spki() {
    let key = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(vec!["localhost".to_owned()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let expected: [u8; PIN_LEN] = Sha256::digest(key.public_key_der()).into();
    assert_eq!(spki_pin(cert.der()), Some(expected));
}
