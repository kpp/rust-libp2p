// Copyright 2021 Parity Technologies (UK) Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

//! TLS configuration for QUIC based on libp2p TLS specs.

pub mod certificate;
pub mod verifier;

use std::sync::Arc;
use thiserror::Error;

use rustls::{SupportedCipherSuite,
    ciphersuite::{
        TLS13_CHACHA20_POLY1305_SHA256,
        TLS13_AES_256_GCM_SHA384,
        TLS13_AES_128_GCM_SHA256,
    },
};

/// A list of the TLS 1.3 cipher suites supported by rustls.
// By default rustls creates client/server configs with both
// TLS 1.3 __and__ 1.2 cipher suites. But we don't need 1.2.
pub static TLS13_CIPHERSUITES: [&SupportedCipherSuite; 3] = [
    // TLS1.3 suites
    &TLS13_CHACHA20_POLY1305_SHA256,
    &TLS13_AES_256_GCM_SHA384,
    &TLS13_AES_128_GCM_SHA256,
];

const P2P_ALPN: [u8; 6] = *b"libp2p";

/// Error creating a configuration
// TODO: remove this; what is the user supposed to do with this error?
#[derive(Debug, Error)]
pub enum ConfigError {
    /// TLS private key or certificate rejected
    #[error("TLS private or certificate key rejected: {0}")]
    TLSError(#[from] rustls::TLSError),
    /// Signing failed
    #[error("Signing failed: {0}")]
    SigningError(#[from] libp2p_core::identity::error::SigningError),
    /// Certificate generation error
    #[error("Certificate generation error: {0}")]
    RcgenError(#[from] rcgen::RcgenError),
}

// FIXME: the architecture should be fixed in order to verify
// P2pExtension::public_key in ServerCertVerifier::verify_server_cert
// with the peer ID of the peer it is connecting to.
fn make_client_config(
    certificate: rustls::Certificate,
    key: rustls::PrivateKey,
    verifier: Arc<verifier::Libp2pCertificateVerifier>,
) -> Result<rustls::ClientConfig, rustls::TLSError> {
    let mut crypto = rustls::ClientConfig::with_ciphersuites(&TLS13_CIPHERSUITES);
    crypto.versions = vec![rustls::ProtocolVersion::TLSv1_3];
    crypto.set_protocols(&[P2P_ALPN.to_vec()]);
    crypto.set_single_client_cert(vec![certificate], key)?;
    crypto.dangerous().set_certificate_verifier(verifier);
    Ok(crypto)
}

fn make_server_config(
    certificate: rustls::Certificate,
    key: rustls::PrivateKey,
    verifier: Arc<verifier::Libp2pCertificateVerifier>,
) -> Result<rustls::ServerConfig, rustls::TLSError> {
    let mut crypto = rustls::ServerConfig::with_ciphersuites(verifier, &TLS13_CIPHERSUITES);
    crypto.versions = vec![rustls::ProtocolVersion::TLSv1_3];
    crypto.set_protocols(&[P2P_ALPN.to_vec()]);
    crypto.set_single_cert(vec![certificate], key)?;
    Ok(crypto)
}

/// Create TLS client and server configurations for libp2p.
pub fn make_tls_config(
    keypair: &libp2p_core::identity::Keypair,
) -> Result<(rustls::ClientConfig, rustls::ServerConfig), ConfigError> {
    let cert = certificate::make_certificate(&keypair)?;
    let private_key = cert.serialize_private_key_der();
    let verifier = Arc::new(verifier::Libp2pCertificateVerifier);
    let cert = rustls::Certificate(cert.serialize_der()?);
    let key = rustls::PrivateKey(private_key);
    Ok((
        make_client_config(cert.clone(), key.clone(), verifier.clone())?,
        make_server_config(cert, key, verifier)?,
    ))
}
