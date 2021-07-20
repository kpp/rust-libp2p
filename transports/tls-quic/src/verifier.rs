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

//! TLS 1.3 certificates and handshakes handling for libp2p
//!
//! This module handles a verification of a client/server certificate chain
//! and signatures allegedly by the given certificates.

use rustls::{
    internal::msgs::handshake::DigitallySignedStruct,
    Certificate, ClientCertVerified, DistinguishedNames,
    HandshakeSignatureValid, RootCertStore, ServerCertVerified,
    SignatureScheme, TLSError,
};

/// Implementation of the `rustls` certificate verification traits for libp2p.
///
/// Only TLS 1.3 is supported. TLS 1.2 should be disabled in the configuration of `rustls`.
pub struct Libp2pCertificateVerifier;

impl Libp2pCertificateVerifier {
    /// Return the list of SignatureSchemes that this verifier will handle,
    /// in `verify_tls12_signature` and `verify_tls13_signature` calls.
    ///
    /// This should be in priority order, with the most preferred first.
    pub fn verification_schemes() -> Vec<SignatureScheme> {
        vec![
            // TODO SignatureScheme::ECDSA_NISTP521_SHA512 is not supported by `ring` yet
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            // TODO SignatureScheme::ED448 is not supported by `ring` yet
            SignatureScheme::ED25519,

            // In particular, RSA SHOULD NOT be used unless
            // no elliptic curve algorithms are supported.
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA256,
        ]
    }
}

impl rustls::ServerCertVerifier for Libp2pCertificateVerifier {
    fn verify_server_cert(
        &self,
        _roots: &RootCertStore,
        presented_certs: &[Certificate],
        _dns_name: webpki::DNSNameRef<'_>,
        _ocsp_response: &[u8],
    ) -> Result<ServerCertVerified, TLSError> {
        verify_certs(presented_certs).map(|_| ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &Certificate,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TLSError> {
        // The libp2p handshake uses TLS 1.3 (and higher).
        // Endpoints MUST NOT negotiate lower TLS versions.
        Err(TLSError::PeerIncompatibleError("Only TLS 1.3 certificates are supported".to_string()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &Certificate,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TLSError> {
        verify_tls13_signature(cert, dss.scheme, message, dss.sig.0.as_ref())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        Self::verification_schemes()
    }
}

impl rustls::ClientCertVerifier for Libp2pCertificateVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_root_subjects(
        &self,
        _dns_name: Option<&webpki::DNSName>,
    ) -> Option<DistinguishedNames> {
        Some(vec![])
    }

    fn verify_client_cert(
        &self,
        presented_certs: &[Certificate],
        _dns_name: Option<&webpki::DNSName>,
    ) -> Result<ClientCertVerified, TLSError> {
        verify_certs(presented_certs).map(|_| ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &Certificate,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TLSError> {
        // The libp2p handshake uses TLS 1.3 (and higher).
        // Endpoints MUST NOT negotiate lower TLS versions.
        Err(TLSError::PeerIncompatibleError("Only TLS 1.3 certificates are supported".to_string()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &Certificate,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TLSError> {
        verify_tls13_signature(cert, dss.scheme, message, dss.sig.0.as_ref())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        Self::verification_schemes()
    }
}

/// When receiving the certificate chain, an endpoint
/// MUST check these conditions and abort the connection attempt if
/// (a) the presented certificate is not yet valid, OR
/// (b) if it is expired.
/// Endpoints MUST abort the connection attempt if more than one certificate is received,
/// or if the certificate’s self-signature is not valid.
fn verify_certs(presented_certs: &[Certificate]) -> Result<(), TLSError> {
    if presented_certs.len() != 1 {
        return Err(TLSError::NoCertificatesPresented);
    }
    let certificate = crate::certificate::parse_certificate(presented_certs[0].as_ref())
        .map_err(|_| {
            // There are multiple reasons for it:
            // - Invalid DER
            // - Incomplete DER
            // - DuplicateExtensions
            // - InvalidExtensions
            // - and so on
            // But there is no reason to distinguish them at the moment.
            // Let's assume the ceritiface was badly constructed:
            TLSError::WebPKIError(webpki::Error::BadDER)
        })?;

    if certificate.is_valid() {
        Ok(())
    } else {
        // There are multiple reasons for it:
        // - InvalidCertValidity
        // - BadDER
        // - UnknownIssuer
        // - UnsupportedSignatureAlgorithm
        // - UnsupportedSignatureAlgorithmForPublicKey
        // - InvalidSignatureForPublicKey
        // But there is no reason to distinguish them at the moment.
        // Let's assume a worst-case scenario:
        Err(TLSError::WebPKIError(webpki::Error::InvalidSignatureForPublicKey))
    }
}

fn verify_tls13_signature(
    cert: &Certificate,
    signature_scheme: SignatureScheme,
    message: &[u8],
    signature: &[u8],
) -> Result<HandshakeSignatureValid, TLSError> {
    let certificate = crate::certificate::parse_certificate(cert.as_ref())
        .map_err(|_| {
            // There are multiple reasons for it:
            // - Invalid DER
            // - Incomplete DER
            // - DuplicateExtensions
            // - InvalidExtensions
            // - and so on
            // But there is no reason to distinguish them at the moment.
            // Let's assume the ceritiface was badly constructed:
            TLSError::WebPKIError(webpki::Error::BadDER)
        })?;
    if certificate.verify_signature(signature_scheme, message, signature) {
        Ok(HandshakeSignatureValid::assertion())
    } else {
        // There are multiple reasons for it:
        // - UnsupportedSignatureAlgorithmForPublicKey
        // - InvalidSignatureForPublicKey
        // But there is no reason to distinguish them at the moment.
        // Let's assume a worst-case scenario:
        Err(TLSError::WebPKIError(webpki::Error::InvalidSignatureForPublicKey))
    }
}
