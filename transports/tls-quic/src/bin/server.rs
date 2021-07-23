use libp2p_tls_quic::certificate;
use libp2p_tls_quic::verifier;

use quinn_proto::Connection as QuicConnection;

use std::sync::Arc;
use std::net::UdpSocket;
use std::time::Instant;
use std::collections::HashMap;

//use quinn_proto::crypto::rustls::QUIC_CIPHER_SUITES;
use rustls::{SupportedCipherSuite, 
    ciphersuite::{
        TLS13_CHACHA20_POLY1305_SHA256,
        TLS13_AES_256_GCM_SHA384,
        TLS13_AES_128_GCM_SHA256,
    },
};

/// A list of the TLS 1.3 cipher suites supported by rustls.
pub static TLS13_CIPHERSUITES: [&SupportedCipherSuite; 3] = [
    // TLS1.3 suites
    &TLS13_CHACHA20_POLY1305_SHA256,
    &TLS13_AES_256_GCM_SHA384,
    &TLS13_AES_128_GCM_SHA256,
];

fn make_client_config(
    certificate: rustls::Certificate,
    key: rustls::PrivateKey,
) -> Result<rustls::ClientConfig, rustls::TLSError> {
    let mut crypto = rustls::ClientConfig::with_ciphersuites(&TLS13_CIPHERSUITES);
    crypto.versions = vec![rustls::ProtocolVersion::TLSv1_3];
    crypto.set_protocols(&[b"libp2p".to_vec()]);
    crypto.enable_early_data = false;
    crypto.set_single_client_cert(vec![certificate], key)?;
    crypto.dangerous().set_certificate_verifier(Arc::new(verifier::Libp2pCertificateVerifier));
    Ok(crypto)
}

fn make_server_config(
    certificate: rustls::Certificate,
    key: rustls::PrivateKey,
) -> Result<rustls::ServerConfig, rustls::TLSError> {
    let mut crypto = rustls::ServerConfig::with_ciphersuites(Arc::new(verifier::Libp2pCertificateVerifier), &TLS13_CIPHERSUITES);
    crypto.versions = vec![rustls::ProtocolVersion::TLSv1_3];
    crypto.set_protocols(&[b"libp2p".to_vec()]);
    crypto.set_single_cert(vec![certificate], key)?;
    Ok(crypto)
}

/// Create TLS client and server configurations for libp2p.
pub fn make_tls_config(
    cert: rcgen::Certificate,
) -> Result<(rustls::ClientConfig, rustls::ServerConfig), rustls::TLSError> {
    let private_key = cert.serialize_private_key_der();
    let cert_der = cert.serialize_der().unwrap();
    let cert = rustls::Certificate(cert_der);
    let key = rustls::PrivateKey(private_key);
    Ok((
        make_client_config(cert.clone(), key.clone())?,
        make_server_config(cert, key)?,
    ))
}

fn main() {
    let keypair = libp2p_core::identity::Keypair::generate_ed25519();
    dbg!(libp2p_core::PeerId::from_public_key(keypair.public()));
    let cert = certificate::make_certificate(&keypair).unwrap();

    let mut transport = quinn_proto::TransportConfig::default();
    // We don't use datagrams or unidirectional streams
    // according to the go implementation of libp2p-quic.
    transport.max_concurrent_uni_streams(42).unwrap();  // Can only panic if value is out of range.
    transport.max_concurrent_bidi_streams(42).unwrap();  // Can only panic if value is out of range.
    //transport.datagram_receive_buffer_size(None);
    //transport.keep_alive_interval(Some(core::time::Duration::from_millis(10)));
    let transport = Arc::new(transport);

    let (client_tls_config, server_tls_config) = make_tls_config(cert).unwrap();

    let server_quic_config = {
        let mut server_config = quinn_proto::ServerConfig::default();
        server_config.transport = transport.clone();
        server_config.crypto = Arc::new(server_tls_config);
        //server_config.concurrent_connections(42);
        //server_config.crypto.set_client_certificate_verifier();
        Arc::new(server_config)
    };

    let _client_quic_config = {
        let mut client_config = quinn_proto::ClientConfig::default();
        client_config.transport = transport;
        client_config.crypto = Arc::new(client_tls_config);
        //client_config.crypto.dangerous().set_certificate_verifier();
        Arc::new(client_config)
    };

    let endpoint_config = Arc::new(quinn_proto::EndpointConfig::default());

    // The actual QUIC state machine.
    let mut endpoint = quinn_proto::Endpoint::new(
        endpoint_config,
        Some(server_quic_config.clone()),
    );

    let mut alive_connections = HashMap::<quinn_proto::ConnectionHandle, QuicConnection>::new();

    let udp_socket = UdpSocket::bind("127.0.0.1:8383").unwrap();
    let local_ip = udp_socket.local_addr().ok().map(|addr| addr.ip());
    // Buffer where we write packets received from the UDP socket.
    let mut socket_recv_buffer = vec![0; 65536];

    let mut iteration = 1;
    
    loop {
        println!("\n\n============================ {}\n\n", iteration);
        iteration += 1;

        //assert!(endpoint.poll_transmit().is_none());

        let (packet_len, packet_src) = udp_socket.recv_from(&mut socket_recv_buffer).unwrap();
        debug_assert!(packet_len <= socket_recv_buffer.len());
        let packet = From::from(&socket_recv_buffer[..packet_len]);
        // TODO: ECN bits aren't handled
        let event = endpoint.handle(Instant::now(), packet_src, local_ip, None, packet).unwrap();
        match event {
            (connec_id, quinn_proto::DatagramEvent::ConnectionEvent(event)) => {
                dbg!("connection event", connec_id.0);
                let connection = alive_connections.get_mut(&connec_id).unwrap();

                //dbg!(&event);
                connection.handle_event(event);

                loop {
                    let mut had_events = false;

                    while let Some(transmit) = connection.poll_transmit(Instant::now()) {
                        dbg!("send data");
                        let s = udp_socket.send_to(&transmit.contents, transmit.destination).unwrap();
                        assert_eq!(s, transmit.contents.len());
                    }

                    while let Some(endpoint_event) = connection.poll_endpoint_events() {
                        dbg!("endpoint_event");
                        let connection_event = endpoint.handle_event(connec_id, endpoint_event);
                        if let Some(connection_event) = connection_event {
                            dbg!("connection_event");
                            connection.handle_event(connection_event);
                            had_events = true;
                        }
                    }

                    while let Some(event) = connection.poll() {
                        dbg!(event);
                    }
                    if !had_events {
                        break;
                    }
                }

                assert!(connection.poll_transmit(Instant::now()).is_none());
                assert!(connection.poll_endpoint_events().is_none());
                assert!(connection.poll().is_none());
                assert!(connection.streams().accept(quinn_proto::Dir::Bi).is_none());
                assert!(connection.streams().accept(quinn_proto::Dir::Uni).is_none());
            },
            (connec_id, quinn_proto::DatagramEvent::NewConnection(mut connection)) => {
                dbg!("new connection");

                loop {
                    let mut had_events = false;

                    while let Some(transmit) = connection.poll_transmit(Instant::now()) {
                        dbg!("send data");
                        let s = udp_socket.send_to(&transmit.contents, transmit.destination).unwrap();
                        assert_eq!(s, transmit.contents.len());
                    }

                    while let Some(endpoint_event) = connection.poll_endpoint_events() {
                        dbg!("endpoint_event");
                        let connection_event = endpoint.handle_event(connec_id, endpoint_event);
                        if let Some(connection_event) = connection_event {
                            dbg!("connection_event");
                            connection.handle_event(connection_event);
                            had_events = true;
                        }
                    }

                    while let Some(event) = connection.poll() {
                        dbg!(event);
                    }
                    if !had_events {
                        break;
                    }
                }

                assert!(connection.poll_transmit(Instant::now()).is_none());
                assert!(connection.poll_endpoint_events().is_none());
                assert!(connection.poll().is_none());
                assert!(connection.streams().accept(quinn_proto::Dir::Bi).is_none());
                assert!(connection.streams().accept(quinn_proto::Dir::Uni).is_none());

                alive_connections.insert(connec_id, connection);
            },
        };
    }
}
