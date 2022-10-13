// Copyright 2020 Parity Technologies (UK) Ltd.
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

use crate::endpoint::{self, ToEndpoint};
use futures::{channel::mpsc, prelude::*};
use futures_timer::Delay;
use libp2p_core::PeerId;
use std::{
    net::SocketAddr,
    task::{Context, Poll},
    time::Instant,
};

/// A state machine for a single QUIC connection.
///
/// This state machine wraps around a [`quinn_proto::Connection`] state machine and implements most
/// of the libp2p-specific functionality of a QUIC connection. For example, libp2p only uses
/// bi-directional streams which is why this state machine does not expose QUIC's uni-directional
/// streams.
///
/// This state machine assumes that a corresponding [`EndpointDriver`](super::endpoint::EndpointDriver)
/// will processes its messages.
#[derive(Debug)]
pub struct State {
    /// Channel to the endpoint this connection belongs to.
    endpoint_channel: endpoint::Channel,
    /// Pending message to be sent to the background task that is driving the endpoint.
    pending_to_endpoint: Option<ToEndpoint>,
    /// Events that the endpoint will send in destination to our local [`quinn_proto::Connection`].
    /// Passed at initialization.
    from_endpoint: mpsc::Receiver<quinn_proto::ConnectionEvent>,
    /// The QUIC state machine for this specific connection.
    connection: quinn_proto::Connection,
    /// Identifier for this connection according to the endpoint. Used when sending messages to
    /// the endpoint.
    connection_id: quinn_proto::ConnectionHandle,
    /// `Future` that triggers at the [`Instant`] that `self.connection.poll_timeout()` indicates.
    next_timeout: Option<(Delay, Instant)>,
}

/// Error on the connection as a whole.
#[derive(Debug, Clone, thiserror::Error)]
pub enum Error {
    /// The task driving the endpoint has crashed.
    #[error("Endpoint driver crashed")]
    EndpointDriverCrashed,

    /// Error in the inner state machine.
    #[error(transparent)]
    Quinn(#[from] quinn_proto::ConnectionError),
}

impl State {
    /// Crate-internal function that builds a [`State`] from raw components.
    ///
    /// This function assumes that there exists a [`EndpointDriver`](super::endpoint::EndpointDriver)
    /// that will process the messages sent to `EndpointChannel::to_endpoint` and send us messages
    /// on `from_endpoint`.
    ///
    /// `connection_id` is used to identify the local connection in the messages sent to
    /// `to_endpoint`.
    ///
    /// This function assumes that the [`quinn_proto::Connection`] is completely fresh and none of
    /// its methods has ever been called. Failure to comply might lead to logic errors and panics.
    pub fn from_quinn_connection(
        endpoint_channel: endpoint::Channel,
        connection: quinn_proto::Connection,
        connection_id: quinn_proto::ConnectionHandle,
        from_endpoint: mpsc::Receiver<quinn_proto::ConnectionEvent>,
    ) -> Self {
        debug_assert!(!connection.is_closed());
        State {
            endpoint_channel,
            pending_to_endpoint: None,
            connection,
            next_timeout: None,
            from_endpoint,
            connection_id,
        }
    }

    /// The address that the local socket is bound to.
    pub fn local_addr(&self) -> &SocketAddr {
        self.endpoint_channel.socket_addr()
    }

    /// Returns the address of the node we're connected to.
    pub fn remote_addr(&self) -> SocketAddr {
        self.connection.remote_address()
    }

    /// Start closing the connection. A [`ConnectionEvent::ConnectionLost`] event will be
    /// produced in the future.
    pub fn close(&mut self) {
        // We send a dummy `0` error code with no message, as the API of StreamMuxer doesn't
        // support this.
        self.connection
            .close(Instant::now(), From::from(0u32), Default::default());
    }

    /// Whether the connection is closed.
    /// A [`ConnectionEvent::ConnectionLost`] event is emitted with details when the
    /// connection becomes closed.
    pub fn is_closed(&self) -> bool {
        self.connection.is_closed()
    }

    /// Whether there is no longer any need to keep the connection around.
    /// All drained connections have been closed.
    pub fn is_drained(&self) -> bool {
        self.connection.is_drained()
    }

    /// Pops a new substream opened by the remote.
    ///
    /// If `None` is returned, then a [`ConnectionEvent::StreamAvailable`] event will later be
    /// produced when a substream is available.
    pub fn accept_substream(&mut self) -> Option<quinn_proto::StreamId> {
        self.connection.streams().accept(quinn_proto::Dir::Bi)
    }

    /// Pops a new substream opened locally.
    ///
    /// The API can be thought as if outgoing substreams were automatically opened by the local
    /// QUIC connection and were added to a queue for availability.
    ///
    /// If `None` is returned, then a [`ConnectionEvent::StreamOpened`] event will later be
    /// produced when a substream is available.
    pub fn open_substream(&mut self) -> Option<quinn_proto::StreamId> {
        self.connection.streams().open(quinn_proto::Dir::Bi)
    }

    /// Control over the stream for reading.
    pub fn recv_stream(&mut self, id: quinn_proto::StreamId) -> quinn_proto::RecvStream<'_> {
        self.connection.recv_stream(id)
    }

    /// Control over the stream for writing.
    pub fn send_stream(&mut self, id: quinn_proto::StreamId) -> quinn_proto::SendStream<'_> {
        self.connection.send_stream(id)
    }

    /// Number of streams that may have unacknowledged data.
    pub fn send_stream_count(&mut self) -> usize {
        self.connection.streams().send_streams()
    }

    /// Closes the given substream.
    ///
    /// `write_substream` must no longer be called. The substream is however still
    /// readable.
    ///
    /// On success, a [`quinn_proto::StreamEvent::Finished`] event will later be produced when the
    /// substream has been effectively closed. A [`ConnectionEvent::StreamStopped`] event can also
    /// be emitted.
    pub fn finish_substream(
        &mut self,
        id: quinn_proto::StreamId,
    ) -> Result<(), quinn_proto::FinishError> {
        self.connection.send_stream(id).finish()
    }

    /// Polls the connection for an event that happened on it.
    pub fn poll_event(&mut self, cx: &mut Context<'_>) -> Poll<Event> {
        loop {
            match self.from_endpoint.poll_next_unpin(cx) {
                Poll::Ready(Some(event)) => {
                    self.connection.handle_event(event);
                    continue;
                }
                Poll::Ready(None) => {
                    return Poll::Ready(Event::ConnectionLost(Error::EndpointDriverCrashed));
                }
                Poll::Pending => {}
            }

            // Sending the pending event to the endpoint. If the endpoint is too busy, we just
            // stop the processing here.
            // We need to be careful to avoid a potential deadlock if both `from_endpoint` and
            // `to_endpoint` are full. As such, we continue to transfer data from `from_endpoint`
            // to the `quinn_proto::Connection` (see above).
            // However we don't deliver substream-related events to the user as long as
            // `to_endpoint` is full. This should propagate the back-pressure of `to_endpoint`
            // being full to the user.
            if let Some(to_endpoint) = self.pending_to_endpoint.take() {
                match self.endpoint_channel.try_send(to_endpoint, cx) {
                    Ok(Ok(())) => continue, // The endpoint may send back an event.
                    Ok(Err(to_endpoint)) => {
                        self.pending_to_endpoint = Some(to_endpoint);
                        return Poll::Pending;
                    }
                    Err(endpoint::Disconnected {}) => {
                        return Poll::Ready(Event::ConnectionLost(Error::EndpointDriverCrashed));
                    }
                }
            }

            // The maximum amount of segments which can be transmitted in a single Transmit
            // if a platform supports Generic Send Offload (GSO).
            // Set to 1 for now since not all platforms support GSO.
            // TODO: Fix for platforms that support GSO.
            let max_datagrams = 1;
            // Poll the connection for packets to send on the UDP socket and try to send them on
            // `to_endpoint`.
            if let Some(transmit) = self.connection.poll_transmit(Instant::now(), max_datagrams) {
                // TODO: ECN bits not handled
                self.pending_to_endpoint = Some(ToEndpoint::SendUdpPacket(transmit));
                continue;
            }

            match self.connection.poll_timeout() {
                Some(timeout) => match self.next_timeout {
                    Some((_, when)) if when == timeout => {}
                    _ => {
                        let now = Instant::now();
                        // 0ns if now > when
                        let duration = timeout.duration_since(now);
                        let next_timeout = Delay::new(duration);
                        self.next_timeout = Some((next_timeout, timeout))
                    }
                },
                None => self.next_timeout = None,
            }

            if let Some((timeout, when)) = self.next_timeout.as_mut() {
                if timeout.poll_unpin(cx).is_ready() {
                    self.connection.handle_timeout(*when);
                    continue;
                }
            }

            // The connection also needs to be able to send control messages to the endpoint. This is
            // handled here, and we try to send them on `to_endpoint` as well.
            if let Some(event) = self.connection.poll_endpoint_events() {
                let connection_id = self.connection_id;
                self.pending_to_endpoint = Some(ToEndpoint::ProcessConnectionEvent {
                    connection_id,
                    event,
                });
                continue;
            }

            // The final step consists in handling the events related to the various substreams.
            if let Some(ev) = self.connection.poll() {
                let event = self.parse_event(ev);
                return Poll::Ready(event);
            }

            return Poll::Pending;
        }
    }

    fn parse_event(&self, event: quinn_proto::Event) -> Event {
        match event {
            quinn_proto::Event::Connected => {
                let session = self.connection.crypto_session();
                let identity = session
                    .peer_identity()
                    .expect("connection got identity because it passed TLS handshake; qed");
                let certificates: Box<Vec<rustls::Certificate>> =
                    identity.downcast().expect("we rely on rustls feature; qed");
                let end_entity = certificates
                    .get(0)
                    .expect("there should be exactly one certificate; qed");
                let end_entity_der = end_entity.as_ref();
                let p2p_cert = crate::tls::certificate::parse_certificate(end_entity_der)
                    .expect("the certificate was validated during TLS handshake; qed");
                let peer_id = PeerId::from_public_key(&p2p_cert.extension.public_key);
                Event::Connected(peer_id)
            }
            quinn_proto::Event::Stream(quinn_proto::StreamEvent::Readable { id }) => {
                Event::StreamReadable(id)
            }
            quinn_proto::Event::Stream(quinn_proto::StreamEvent::Writable { id }) => {
                Event::StreamWritable(id)
            }
            quinn_proto::Event::Stream(quinn_proto::StreamEvent::Stopped { id, .. }) => {
                Event::StreamStopped(id)
            }
            quinn_proto::Event::Stream(quinn_proto::StreamEvent::Available {
                dir: quinn_proto::Dir::Bi,
            }) => Event::StreamAvailable,
            quinn_proto::Event::Stream(quinn_proto::StreamEvent::Opened {
                dir: quinn_proto::Dir::Bi,
            }) => Event::StreamOpened,
            quinn_proto::Event::ConnectionLost { reason } => {
                Event::ConnectionLost(Error::Quinn(reason))
            }
            quinn_proto::Event::Stream(quinn_proto::StreamEvent::Finished { id }) => {
                Event::StreamFinished(id)
            }
            quinn_proto::Event::HandshakeDataReady => Event::HandshakeDataReady,
            quinn_proto::Event::Stream(quinn_proto::StreamEvent::Opened {
                dir: quinn_proto::Dir::Uni,
            })
            | quinn_proto::Event::Stream(quinn_proto::StreamEvent::Available {
                dir: quinn_proto::Dir::Uni,
            })
            | quinn_proto::Event::DatagramReceived => {
                unreachable!("We don't use datagrams or unidirectional streams.")
            }
        }
    }
}

impl Drop for State {
    fn drop(&mut self) {
        let to_endpoint = ToEndpoint::ProcessConnectionEvent {
            connection_id: self.connection_id,
            event: quinn_proto::EndpointEvent::drained(),
        };
        self.endpoint_channel.send_on_drop(to_endpoint);
    }
}

/// Event generated by the [`Connection`].
#[derive(Debug)]
pub enum Event {
    /// Now connected to the remote and certificates are available.
    Connected(PeerId),

    /// Connection has been closed and can no longer be used.
    ConnectionLost(Error),

    /// Generated after [`Connection::accept_substream`] has been called and has returned
    /// `None`. After this event has been generated, this method is guaranteed to return `Some`.
    StreamAvailable,
    /// Generated after [`Connection::open_substream`] has been called and has returned
    /// `None`. After this event has been generated, this method is guaranteed to return `Some`.
    StreamOpened,

    /// Generated after `read_substream` has returned a `Blocked` error.
    StreamReadable(quinn_proto::StreamId),
    /// Generated after `write_substream` has returned a `Blocked` error.
    StreamWritable(quinn_proto::StreamId),

    /// Generated after [`Connection::finish_substream`] has been called.
    StreamFinished(quinn_proto::StreamId),
    /// A substream has been stopped. This concept is similar to the concept of a substream being
    /// "reset", as in a TCP socket being reset for example.
    StreamStopped(quinn_proto::StreamId),

    HandshakeDataReady,
}
