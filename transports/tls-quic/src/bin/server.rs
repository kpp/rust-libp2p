use libp2p_tls_quic::certificate;
use libp2p_tls_quic::verifier;

use quinn_proto::{Connection as QuicConnection, Transmit as QuicTransmit};

use std::sync::Arc;
use std::net::UdpSocket;
use std::time::Instant;
use std::collections::{HashMap, VecDeque};

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
    let mut outbound = VecDeque::<QuicTransmit>::new();
    let mut endpoint_events: Vec<(quinn_proto::ConnectionHandle, quinn_proto::EndpointEvent)> = vec![];
    let mut connection_events = HashMap::<quinn_proto::ConnectionHandle, VecDeque::<quinn_proto::ConnectionEvent>>::new();

    let mut timeout = None;

    let udp_socket = UdpSocket::bind("127.0.0.1:8383").unwrap();
    let local_ip = udp_socket.local_addr().ok().map(|addr| addr.ip());
    // Buffer where we write packets received from the UDP socket.
    let mut socket_recv_buffer = vec![0; 65536];

    let mut iteration = 1;
    
    loop {
        println!("\n\n============================ {}\n\n", iteration);
        iteration += 1;

        let (packet_len, packet_src) = udp_socket.recv_from(&mut socket_recv_buffer).unwrap();
        debug_assert!(packet_len <= socket_recv_buffer.len());
        let packet = From::from(&socket_recv_buffer[..packet_len]);
        let now = Instant::now();
        // TODO: ECN bits aren't handled
        let event = endpoint.handle(now, packet_src, local_ip, None, packet).unwrap();
        match event {
            (connec_id, quinn_proto::DatagramEvent::ConnectionEvent(event)) => {
                dbg!("connection event", connec_id.0);
                connection_events.entry(connec_id)
                    .or_insert_with(VecDeque::new)
                    .push_back(event);
            },
            (connec_id, quinn_proto::DatagramEvent::NewConnection(connection)) => {
                dbg!("new connection", connec_id.0);
                alive_connections.insert(connec_id, connection);
            },
        };

        while let Some(transmit) = endpoint.poll_transmit() {
            dbg!("push endpoint outbound");
            outbound.push_back(transmit);
        }

        for (ch, connection) in alive_connections.iter_mut() {
            if timeout.map_or(false, |x| x <= now) {
                timeout = None;
                connection.handle_timeout(now);
            }

            if let Some(events) = connection_events.get_mut(ch) {
                for event in events.drain(..) {
                    dbg!("connection_event");
                    connection.handle_event(event);
                }
            }

            while let Some(endpoint_event) = connection.poll_endpoint_events() {
                dbg!("push endpoint_event");
                endpoint_events.push((*ch, endpoint_event));
            }

            while let Some(transmit) = connection.poll_transmit(now) {
                dbg!("push connection outbound");
                outbound.push_back(transmit);
            }

            timeout = connection.poll_timeout();
        }

        for (ch, event) in endpoint_events.drain(..) {
            let connection_event = endpoint.handle_event(ch, event);
            if let Some(connection_event) = connection_event {
                dbg!("connection_event from endpoint");
                //dbg!(&connection_event);
                if let Some(connection) = alive_connections.get_mut(&ch) {
                    connection.handle_event(connection_event);
                }
            }
        }

        for transmit in outbound.drain(..) {
            dbg!("send_data");
            assert!(transmit.segment_size.is_none());
            let s = udp_socket.send_to(&transmit.contents, transmit.destination).unwrap();
            assert_eq!(s, transmit.contents.len());
        }

        let mut events = vec![];
        for (ch, connection) in alive_connections.iter_mut() {
            while let Some(event) = connection.poll() {
                events.push((*ch, event));
            }
        }

        for (ch, event) in events {
            dbg!(&event);
            use quinn_proto::Event::*;
            match event {
                HandshakeDataReady => {

                },
                Connected => {

                },
                ConnectionLost{reason} => {
                    let _ = reason;
                    alive_connections.remove(&ch);
                    connection_events.remove(&ch);
                },
                Stream(_) => {

                },
                DatagramReceived => {

                },
            }
        }
    }
}
