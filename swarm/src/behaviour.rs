// Copyright 2019 Parity Technologies (UK) Ltd.
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

mod either;
pub mod toggle;

use crate::dial_opts::DialOpts;
use crate::handler::{ConnectionHandler, IntoConnectionHandler};
use crate::{AddressRecord, AddressScore, DialError};
use libp2p_core::{
    connection::ConnectionId, transport::ListenerId, ConnectedPoint, Multiaddr, PeerId,
};
use std::{task::Context, task::Poll};

/// Custom event that can be received by the [`ConnectionHandler`].
pub(crate) type THandlerInEvent<THandler> =
    <<THandler as IntoConnectionHandler>::Handler as ConnectionHandler>::InEvent;

pub(crate) type THandlerOutEvent<THandler> =
    <<THandler as IntoConnectionHandler>::Handler as ConnectionHandler>::OutEvent;

/// A [`NetworkBehaviour`] defines the behaviour of the local node on the network.
///
/// In contrast to [`Transport`](libp2p_core::Transport) which defines **how** to send bytes on the
/// network, [`NetworkBehaviour`] defines **what** bytes to send and **to whom**.
///
/// Each protocol (e.g. `libp2p-ping`, `libp2p-identify` or `libp2p-kad`) implements
/// [`NetworkBehaviour`]. Multiple implementations of [`NetworkBehaviour`] can be composed into a
/// hierarchy of [`NetworkBehaviour`]s where parent implementations delegate to child
/// implementations. Finally the root of the [`NetworkBehaviour`] hierarchy is passed to
/// [`Swarm`](crate::Swarm) where it can then control the behaviour of the local node on a libp2p
/// network.
///
/// # Hierarchy of [`NetworkBehaviour`]
///
/// To compose multiple [`NetworkBehaviour`] implementations into a single [`NetworkBehaviour`]
/// implementation, potentially building a multi-level hierarchy of [`NetworkBehaviour`]s, one can
/// use one of the [`NetworkBehaviour`] combinators, and/or use the [`NetworkBehaviour`] derive
/// macro.
///
/// ## Combinators
///
/// [`NetworkBehaviour`] combinators wrap one or more [`NetworkBehaviour`] implementations and
/// implement [`NetworkBehaviour`] themselves. Example is the
/// [`Toggle`](crate::behaviour::toggle::Toggle) [`NetworkBehaviour`].
///
/// ``` rust
/// # use libp2p_swarm::DummyBehaviour;
/// # use libp2p_swarm::behaviour::toggle::Toggle;
/// let my_behaviour = DummyBehaviour::default();
/// let my_toggled_behaviour = Toggle::from(Some(my_behaviour));
/// ```
///
/// ## Custom [`NetworkBehaviour`] with the Derive Macro
///
/// One can derive [`NetworkBehaviour`] for a custom `struct` via the `#[derive(NetworkBehaviour)]`
/// proc macro re-exported by the `libp2p` crate. The macro generates a delegating `trait`
/// implementation for the custom `struct`. Each [`NetworkBehaviour`] trait method is simply
/// delegated to each `struct` member in the order the `struct` is defined. For example for
/// [`NetworkBehaviour::poll`] it will first poll the first `struct` member until it returns
/// [`Poll::Pending`] before moving on to later members. For [`NetworkBehaviour::addresses_of_peer`]
/// it will delegate to each `struct` member and return a concatenated array of all addresses
/// returned by the struct members.
///
/// Events ([`NetworkBehaviour::OutEvent`]) returned by each `struct` member are wrapped in a new
/// `enum` event, with an `enum` variant for each `struct` member. Users can define this event
/// `enum` themselves and provide the name to the derive macro via `#[behaviour(out_event =
/// "MyCustomOutEvent")]`. If the user does not specify an `out_event`, the derive macro generates
/// the event definition itself, naming it `<STRUCT_NAME>Event`.
///
/// The aforementioned conversion of each of the event types generated by the struct members to the
/// custom `out_event` is handled by [`From`] implementations which the user needs to define in
/// addition to the event `enum` itself.
///
/// ``` rust
/// # use libp2p::identify::{Identify, IdentifyEvent};
/// # use libp2p::ping::{Ping, PingEvent};
/// # use libp2p::NetworkBehaviour;
/// #[derive(NetworkBehaviour)]
/// #[behaviour(out_event = "Event")]
/// struct MyBehaviour {
///   identify: Identify,
///   ping: Ping,
/// }
///
/// enum Event {
///   Identify(IdentifyEvent),
///   Ping(PingEvent),
/// }
///
/// impl From<IdentifyEvent> for Event {
///   fn from(event: IdentifyEvent) -> Self {
///     Self::Identify(event)
///   }
/// }
///
/// impl From<PingEvent> for Event {
///   fn from(event: PingEvent) -> Self {
///     Self::Ping(event)
///   }
/// }
/// ```
///
/// Struct members that don't implement [`NetworkBehaviour`] must be annotated with
/// `#[behaviour(ignore)]`.
///
/// ``` rust
/// # use libp2p::identify::{Identify, IdentifyEvent};
/// # use libp2p::ping::{Ping, PingEvent};
/// # use libp2p::NetworkBehaviour;
/// #[derive(NetworkBehaviour)]
/// #[behaviour(out_event = "Event")]
/// struct MyBehaviour {
///   identify: Identify,
///   ping: Ping,
///
///   #[behaviour(ignore)]
///   some_string: String,
/// }
/// #
/// # enum Event {
/// #   Identify(IdentifyEvent),
/// #   Ping(PingEvent),
/// # }
/// #
/// # impl From<IdentifyEvent> for Event {
/// #   fn from(event: IdentifyEvent) -> Self {
/// #     Self::Identify(event)
/// #   }
/// # }
/// #
/// # impl From<PingEvent> for Event {
/// #   fn from(event: PingEvent) -> Self {
/// #     Self::Ping(event)
/// #   }
/// # }
/// ```
pub trait NetworkBehaviour: 'static {
    /// Handler for all the protocols the network behaviour supports.
    type ConnectionHandler: IntoConnectionHandler;

    /// Event generated by the `NetworkBehaviour` and that the swarm will report back.
    type OutEvent: Send + 'static;

    /// Creates a new [`ConnectionHandler`] for a connection with a peer.
    ///
    /// Every time an incoming connection is opened, and every time another [`NetworkBehaviour`]
    /// emitted a dial request, this method is called.
    ///
    /// The returned object is a handler for that specific connection, and will be moved to a
    /// background task dedicated to that connection.
    ///
    /// The network behaviour (ie. the implementation of this trait) and the handlers it has spawned
    /// (ie. the objects returned by `new_handler`) can communicate by passing messages. Messages
    /// sent from the handler to the behaviour are injected with [`NetworkBehaviour::inject_event`],
    /// and the behaviour can send a message to the handler by making [`NetworkBehaviour::poll`]
    /// return [`NetworkBehaviourAction::NotifyHandler`].
    ///
    /// Note that the handler is returned to the [`NetworkBehaviour`] on connection failure and
    /// connection closing.
    fn new_handler(&mut self) -> Self::ConnectionHandler;

    /// Addresses that this behaviour is aware of for this specific peer, and that may allow
    /// reaching the peer.
    ///
    /// The addresses will be tried in the order returned by this function, which means that they
    /// should be ordered by decreasing likelihood of reachability. In other words, the first
    /// address should be the most likely to be reachable.
    fn addresses_of_peer(&mut self, _: &PeerId) -> Vec<Multiaddr> {
        vec![]
    }

    /// Informs the behaviour about a newly established connection to a peer.
    fn inject_connection_established(
        &mut self,
        _peer_id: &PeerId,
        _connection_id: &ConnectionId,
        _endpoint: &ConnectedPoint,
        _failed_addresses: Option<&Vec<Multiaddr>>,
        _other_established: usize,
    ) {
    }

    /// Informs the behaviour about a closed connection to a peer.
    ///
    /// A call to this method is always paired with an earlier call to
    /// [`NetworkBehaviour::inject_connection_established`] with the same peer ID, connection ID and endpoint.
    fn inject_connection_closed(
        &mut self,
        _: &PeerId,
        _: &ConnectionId,
        _: &ConnectedPoint,
        _: <Self::ConnectionHandler as IntoConnectionHandler>::Handler,
        _remaining_established: usize,
    ) {
    }

    /// Informs the behaviour that the [`ConnectedPoint`] of an existing connection has changed.
    fn inject_address_change(
        &mut self,
        _: &PeerId,
        _: &ConnectionId,
        _old: &ConnectedPoint,
        _new: &ConnectedPoint,
    ) {
    }

    /// Informs the behaviour about an event generated by the handler dedicated to the peer identified by `peer_id`.
    /// for the behaviour.
    ///
    /// The `peer_id` is guaranteed to be in a connected state. In other words,
    /// [`NetworkBehaviour::inject_connection_established`] has previously been called with this `PeerId`.
    fn inject_event(
        &mut self,
        peer_id: PeerId,
        connection: ConnectionId,
        event: <<Self::ConnectionHandler as IntoConnectionHandler>::Handler as ConnectionHandler>::OutEvent,
    );

    /// Indicates to the behaviour that the dial to a known or unknown node failed.
    fn inject_dial_failure(
        &mut self,
        _peer_id: Option<PeerId>,
        _handler: Self::ConnectionHandler,
        _error: &DialError,
    ) {
    }

    /// Indicates to the behaviour that an error happened on an incoming connection during its
    /// initial handshake.
    ///
    /// This can include, for example, an error during the handshake of the encryption layer, or the
    /// connection unexpectedly closed.
    fn inject_listen_failure(
        &mut self,
        _local_addr: &Multiaddr,
        _send_back_addr: &Multiaddr,
        _handler: Self::ConnectionHandler,
    ) {
    }

    /// Indicates to the behaviour that a new listener was created.
    fn inject_new_listener(&mut self, _id: ListenerId) {}

    /// Indicates to the behaviour that we have started listening on a new multiaddr.
    fn inject_new_listen_addr(&mut self, _id: ListenerId, _addr: &Multiaddr) {}

    /// Indicates to the behaviour that a multiaddr we were listening on has expired,
    /// which means that we are no longer listening in it.
    fn inject_expired_listen_addr(&mut self, _id: ListenerId, _addr: &Multiaddr) {}

    /// A listener experienced an error.
    fn inject_listener_error(&mut self, _id: ListenerId, _err: &(dyn std::error::Error + 'static)) {
    }

    /// A listener closed.
    fn inject_listener_closed(&mut self, _id: ListenerId, _reason: Result<(), &std::io::Error>) {}

    /// Indicates to the behaviour that we have discovered a new external address for us.
    fn inject_new_external_addr(&mut self, _addr: &Multiaddr) {}

    /// Indicates to the behaviour that an external address was removed.
    fn inject_expired_external_addr(&mut self, _addr: &Multiaddr) {}

    /// Polls for things that swarm should do.
    ///
    /// This API mimics the API of the `Stream` trait. The method may register the current task in
    /// order to wake it up at a later point in time.
    fn poll(
        &mut self,
        cx: &mut Context<'_>,
        params: &mut impl PollParameters,
    ) -> Poll<NetworkBehaviourAction<Self::OutEvent, Self::ConnectionHandler>>;
}

/// Parameters passed to `poll()`, that the `NetworkBehaviour` has access to.
pub trait PollParameters {
    /// Iterator returned by [`supported_protocols`](PollParameters::supported_protocols).
    type SupportedProtocolsIter: ExactSizeIterator<Item = Vec<u8>>;
    /// Iterator returned by [`listened_addresses`](PollParameters::listened_addresses).
    type ListenedAddressesIter: ExactSizeIterator<Item = Multiaddr>;
    /// Iterator returned by [`external_addresses`](PollParameters::external_addresses).
    type ExternalAddressesIter: ExactSizeIterator<Item = AddressRecord>;

    /// Returns the list of protocol the behaviour supports when a remote negotiates a protocol on
    /// an inbound substream.
    ///
    /// The iterator's elements are the ASCII names as reported on the wire.
    ///
    /// Note that the list is computed once at initialization and never refreshed.
    fn supported_protocols(&self) -> Self::SupportedProtocolsIter;

    /// Returns the list of the addresses we're listening on.
    fn listened_addresses(&self) -> Self::ListenedAddressesIter;

    /// Returns the list of the addresses nodes can use to reach us.
    fn external_addresses(&self) -> Self::ExternalAddressesIter;

    /// Returns the peer id of the local node.
    fn local_peer_id(&self) -> &PeerId;
}

/// An action that a [`NetworkBehaviour`] can trigger in the [`Swarm`]
/// in whose context it is executing.
///
/// [`Swarm`]: super::Swarm
//
// Note: `TInEvent` is needed to be able to implement
// [`NetworkBehaviourAction::map_in`], mapping the handler `InEvent` leaving the
// handler itself untouched.
#[derive(Debug)]
pub enum NetworkBehaviourAction<
    TOutEvent,
    THandler: IntoConnectionHandler,
    TInEvent = THandlerInEvent<THandler>,
> {
    /// Instructs the `Swarm` to return an event when it is being polled.
    GenerateEvent(TOutEvent),

    /// Instructs the swarm to start a dial.
    ///
    /// On success, [`NetworkBehaviour::inject_connection_established`] is invoked.
    /// On failure, [`NetworkBehaviour::inject_dial_failure`] is invoked.
    ///
    /// Note that the provided handler is returned to the [`NetworkBehaviour`] on connection failure
    /// and connection closing. Thus it can be used to carry state, which otherwise would have to be
    /// tracked in the [`NetworkBehaviour`] itself. E.g. a message destined to an unconnected peer
    /// can be included in the handler, and thus directly send on connection success or extracted by
    /// the [`NetworkBehaviour`] on connection failure.
    ///
    /// # Example carrying state in the handler
    ///
    /// ```rust
    /// # use futures::executor::block_on;
    /// # use futures::stream::StreamExt;
    /// # use libp2p::core::connection::ConnectionId;
    /// # use libp2p::core::identity;
    /// # use libp2p::core::transport::{MemoryTransport, Transport};
    /// # use libp2p::core::upgrade::{self, DeniedUpgrade, InboundUpgrade, OutboundUpgrade};
    /// # use libp2p::core::PeerId;
    /// # use libp2p::plaintext::PlainText2Config;
    /// # use libp2p::swarm::{
    /// #     DialError, IntoConnectionHandler, KeepAlive, NegotiatedSubstream,
    /// #     NetworkBehaviour, NetworkBehaviourAction, PollParameters, ConnectionHandler,
    /// #     ConnectionHandlerEvent, ConnectionHandlerUpgrErr, SubstreamProtocol, Swarm, SwarmEvent,
    /// # };
    /// # use libp2p::swarm::dial_opts::{DialOpts, PeerCondition};
    /// # use libp2p::yamux;
    /// # use std::collections::VecDeque;
    /// # use std::task::{Context, Poll};
    /// # use void::Void;
    /// #
    /// # let local_key = identity::Keypair::generate_ed25519();
    /// # let local_public_key = local_key.public();
    /// # let local_peer_id = PeerId::from(local_public_key.clone());
    /// #
    /// # let transport = MemoryTransport::default()
    /// #     .upgrade(upgrade::Version::V1)
    /// #     .authenticate(PlainText2Config { local_public_key })
    /// #     .multiplex(yamux::YamuxConfig::default())
    /// #     .boxed();
    /// #
    /// # let mut swarm = Swarm::new(transport, MyBehaviour::default(), local_peer_id);
    /// #
    /// // Super precious message that we should better not lose.
    /// let message = PreciousMessage("My precious message".to_string());
    ///
    /// // Unfortunately this peer is offline, thus sending our message to it will fail.
    /// let offline_peer = PeerId::random();
    ///
    /// // Let's send it anyways. We should get it back in case connecting to the peer fails.
    /// swarm.behaviour_mut().send(offline_peer, message);
    ///
    /// block_on(async {
    ///     // As expected, sending failed. But great news, we got our message back.
    ///     matches!(
    ///         swarm.next().await.expect("Infinite stream"),
    ///         SwarmEvent::Behaviour(PreciousMessage(_))
    ///     );
    /// });
    ///
    /// #[derive(Default)]
    /// struct MyBehaviour {
    ///     outbox_to_swarm: VecDeque<NetworkBehaviourAction<PreciousMessage, MyHandler>>,
    /// }
    ///
    /// impl MyBehaviour {
    ///     fn send(&mut self, peer_id: PeerId, msg: PreciousMessage) {
    ///         self.outbox_to_swarm
    ///             .push_back(NetworkBehaviourAction::Dial {
    ///                 opts: DialOpts::peer_id(peer_id)
    ///                           .condition(PeerCondition::Always)
    ///                           .build(),
    ///                 handler: MyHandler { message: Some(msg) },
    ///             });
    ///     }
    /// }
    /// #
    /// impl NetworkBehaviour for MyBehaviour {
    ///     # type ConnectionHandler = MyHandler;
    ///     # type OutEvent = PreciousMessage;
    ///     #
    ///     # fn new_handler(&mut self) -> Self::ConnectionHandler {
    ///     #     MyHandler { message: None }
    ///     # }
    ///     #
    ///     #
    ///     # fn inject_event(
    ///     #     &mut self,
    ///     #     _: PeerId,
    ///     #     _: ConnectionId,
    ///     #     _: <<Self::ConnectionHandler as IntoConnectionHandler>::Handler as ConnectionHandler>::OutEvent,
    ///     # ) {
    ///     #     unreachable!();
    ///     # }
    ///     #
    ///     fn inject_dial_failure(
    ///         &mut self,
    ///         _: Option<PeerId>,
    ///         handler: Self::ConnectionHandler,
    ///         _: &DialError,
    ///     ) {
    ///         // As expected, sending the message failed. But lucky us, we got the handler back, thus
    ///         // the precious message is not lost and we can return it back to the user.
    ///         let msg = handler.message.unwrap();
    ///         self.outbox_to_swarm
    ///             .push_back(NetworkBehaviourAction::GenerateEvent(msg))
    ///     }
    ///     #
    ///     # fn poll(
    ///     #     &mut self,
    ///     #     _: &mut Context<'_>,
    ///     #     _: &mut impl PollParameters,
    ///     # ) -> Poll<NetworkBehaviourAction<Self::OutEvent, Self::ConnectionHandler>> {
    ///     #     if let Some(action) = self.outbox_to_swarm.pop_front() {
    ///     #         return Poll::Ready(action);
    ///     #     }
    ///     #     Poll::Pending
    ///     # }
    /// }
    ///
    /// # struct MyHandler {
    /// #     message: Option<PreciousMessage>,
    /// # }
    /// #
    /// # impl ConnectionHandler for MyHandler {
    /// #     type InEvent = Void;
    /// #     type OutEvent = Void;
    /// #     type Error = Void;
    /// #     type InboundProtocol = DeniedUpgrade;
    /// #     type OutboundProtocol = DeniedUpgrade;
    /// #     type InboundOpenInfo = ();
    /// #     type OutboundOpenInfo = Void;
    /// #
    /// #     fn listen_protocol(
    /// #         &self,
    /// #     ) -> SubstreamProtocol<Self::InboundProtocol, Self::InboundOpenInfo> {
    /// #         SubstreamProtocol::new(DeniedUpgrade, ())
    /// #     }
    /// #
    /// #     fn inject_fully_negotiated_inbound(
    /// #         &mut self,
    /// #         _: <Self::InboundProtocol as InboundUpgrade<NegotiatedSubstream>>::Output,
    /// #         _: Self::InboundOpenInfo,
    /// #     ) {
    /// #     }
    /// #
    /// #     fn inject_fully_negotiated_outbound(
    /// #         &mut self,
    /// #         _: <Self::OutboundProtocol as OutboundUpgrade<NegotiatedSubstream>>::Output,
    /// #         _: Self::OutboundOpenInfo,
    /// #     ) {
    /// #     }
    /// #
    /// #     fn inject_event(&mut self, _event: Self::InEvent) {}
    /// #
    /// #     fn inject_dial_upgrade_error(
    /// #         &mut self,
    /// #         _: Self::OutboundOpenInfo,
    /// #         _: ConnectionHandlerUpgrErr<Void>,
    /// #     ) {
    /// #     }
    /// #
    /// #     fn connection_keep_alive(&self) -> KeepAlive {
    /// #         KeepAlive::Yes
    /// #     }
    /// #
    /// #     fn poll(
    /// #         &mut self,
    /// #         _: &mut Context<'_>,
    /// #     ) -> Poll<
    /// #         ConnectionHandlerEvent<
    /// #             Self::OutboundProtocol,
    /// #             Self::OutboundOpenInfo,
    /// #             Self::OutEvent,
    /// #             Self::Error,
    /// #         >,
    /// #     > {
    /// #         todo!("If `Self::message.is_some()` send the message to the remote.")
    /// #     }
    /// # }
    /// # #[derive(Debug, PartialEq, Eq)]
    /// # struct PreciousMessage(String);
    /// ```
    Dial { opts: DialOpts, handler: THandler },

    /// Instructs the `Swarm` to send an event to the handler dedicated to a
    /// connection with a peer.
    ///
    /// If the `Swarm` is connected to the peer, the message is delivered to the
    /// [`ConnectionHandler`] instance identified by the peer ID and connection ID.
    ///
    /// If the specified connection no longer exists, the event is silently dropped.
    ///
    /// Typically the connection ID given is the same as the one passed to
    /// [`NetworkBehaviour::inject_event`], i.e. whenever the behaviour wishes to
    /// respond to a request on the same connection (and possibly the same
    /// substream, as per the implementation of [`ConnectionHandler`]).
    ///
    /// Note that even if the peer is currently connected, connections can get closed
    /// at any time and thus the event may not reach a handler.
    NotifyHandler {
        /// The peer for whom a [`ConnectionHandler`] should be notified.
        peer_id: PeerId,
        /// The options w.r.t. which connection handler to notify of the event.
        handler: NotifyHandler,
        /// The event to send.
        event: TInEvent,
    },

    /// Informs the `Swarm` about an address observed by a remote for
    /// the local node by which the local node is supposedly publicly
    /// reachable.
    ///
    /// It is advisable to issue `ReportObservedAddr` actions at a fixed frequency
    /// per node. This way address information will be more accurate over time
    /// and individual outliers carry less weight.
    ReportObservedAddr {
        /// The observed address of the local node.
        address: Multiaddr,
        /// The score to associate with this observation, i.e.
        /// an indicator for the trusworthiness of this address
        /// relative to other observed addresses.
        score: AddressScore,
    },

    /// Instructs the `Swarm` to initiate a graceful close of one or all connections
    /// with the given peer.
    ///
    /// Note: Closing a connection via
    /// [`NetworkBehaviourAction::CloseConnection`] does not inform the
    /// corresponding [`ConnectionHandler`].
    /// Closing a connection via a [`ConnectionHandler`] can be done
    /// either in a collaborative manner across [`ConnectionHandler`]s
    /// with [`ConnectionHandler::connection_keep_alive`] or directly with
    /// [`ConnectionHandlerEvent::Close`](crate::ConnectionHandlerEvent::Close).
    CloseConnection {
        /// The peer to disconnect.
        peer_id: PeerId,
        /// Whether to close a specific or all connections to the given peer.
        connection: CloseConnection,
    },
}

impl<TOutEvent, THandler: IntoConnectionHandler, TInEventOld>
    NetworkBehaviourAction<TOutEvent, THandler, TInEventOld>
{
    /// Map the handler event.
    pub fn map_in<TInEventNew>(
        self,
        f: impl FnOnce(TInEventOld) -> TInEventNew,
    ) -> NetworkBehaviourAction<TOutEvent, THandler, TInEventNew> {
        match self {
            NetworkBehaviourAction::GenerateEvent(e) => NetworkBehaviourAction::GenerateEvent(e),
            NetworkBehaviourAction::Dial { opts, handler } => {
                NetworkBehaviourAction::Dial { opts, handler }
            }
            NetworkBehaviourAction::NotifyHandler {
                peer_id,
                handler,
                event,
            } => NetworkBehaviourAction::NotifyHandler {
                peer_id,
                handler,
                event: f(event),
            },
            NetworkBehaviourAction::ReportObservedAddr { address, score } => {
                NetworkBehaviourAction::ReportObservedAddr { address, score }
            }
            NetworkBehaviourAction::CloseConnection {
                peer_id,
                connection,
            } => NetworkBehaviourAction::CloseConnection {
                peer_id,
                connection,
            },
        }
    }
}

impl<TOutEvent, THandler: IntoConnectionHandler> NetworkBehaviourAction<TOutEvent, THandler> {
    /// Map the event the swarm will return.
    pub fn map_out<E>(self, f: impl FnOnce(TOutEvent) -> E) -> NetworkBehaviourAction<E, THandler> {
        match self {
            NetworkBehaviourAction::GenerateEvent(e) => NetworkBehaviourAction::GenerateEvent(f(e)),
            NetworkBehaviourAction::Dial { opts, handler } => {
                NetworkBehaviourAction::Dial { opts, handler }
            }
            NetworkBehaviourAction::NotifyHandler {
                peer_id,
                handler,
                event,
            } => NetworkBehaviourAction::NotifyHandler {
                peer_id,
                handler,
                event,
            },
            NetworkBehaviourAction::ReportObservedAddr { address, score } => {
                NetworkBehaviourAction::ReportObservedAddr { address, score }
            }
            NetworkBehaviourAction::CloseConnection {
                peer_id,
                connection,
            } => NetworkBehaviourAction::CloseConnection {
                peer_id,
                connection,
            },
        }
    }
}

impl<TInEvent, TOutEvent, THandlerOld> NetworkBehaviourAction<TOutEvent, THandlerOld>
where
    THandlerOld: IntoConnectionHandler,
    <THandlerOld as IntoConnectionHandler>::Handler: ConnectionHandler<InEvent = TInEvent>,
{
    /// Map the handler.
    pub fn map_handler<THandlerNew>(
        self,
        f: impl FnOnce(THandlerOld) -> THandlerNew,
    ) -> NetworkBehaviourAction<TOutEvent, THandlerNew>
    where
        THandlerNew: IntoConnectionHandler,
        <THandlerNew as IntoConnectionHandler>::Handler: ConnectionHandler<InEvent = TInEvent>,
    {
        match self {
            NetworkBehaviourAction::GenerateEvent(e) => NetworkBehaviourAction::GenerateEvent(e),
            NetworkBehaviourAction::Dial { opts, handler } => NetworkBehaviourAction::Dial {
                opts,
                handler: f(handler),
            },
            NetworkBehaviourAction::NotifyHandler {
                peer_id,
                handler,
                event,
            } => NetworkBehaviourAction::NotifyHandler {
                peer_id,
                handler,
                event,
            },
            NetworkBehaviourAction::ReportObservedAddr { address, score } => {
                NetworkBehaviourAction::ReportObservedAddr { address, score }
            }
            NetworkBehaviourAction::CloseConnection {
                peer_id,
                connection,
            } => NetworkBehaviourAction::CloseConnection {
                peer_id,
                connection,
            },
        }
    }
}

impl<TInEventOld, TOutEvent, THandlerOld> NetworkBehaviourAction<TOutEvent, THandlerOld>
where
    THandlerOld: IntoConnectionHandler,
    <THandlerOld as IntoConnectionHandler>::Handler: ConnectionHandler<InEvent = TInEventOld>,
{
    /// Map the handler and handler event.
    pub fn map_handler_and_in<THandlerNew, TInEventNew>(
        self,
        f_handler: impl FnOnce(THandlerOld) -> THandlerNew,
        f_in_event: impl FnOnce(TInEventOld) -> TInEventNew,
    ) -> NetworkBehaviourAction<TOutEvent, THandlerNew>
    where
        THandlerNew: IntoConnectionHandler,
        <THandlerNew as IntoConnectionHandler>::Handler: ConnectionHandler<InEvent = TInEventNew>,
    {
        match self {
            NetworkBehaviourAction::GenerateEvent(e) => NetworkBehaviourAction::GenerateEvent(e),
            NetworkBehaviourAction::Dial { opts, handler } => NetworkBehaviourAction::Dial {
                opts,
                handler: f_handler(handler),
            },
            NetworkBehaviourAction::NotifyHandler {
                peer_id,
                handler,
                event,
            } => NetworkBehaviourAction::NotifyHandler {
                peer_id,
                handler,
                event: f_in_event(event),
            },
            NetworkBehaviourAction::ReportObservedAddr { address, score } => {
                NetworkBehaviourAction::ReportObservedAddr { address, score }
            }
            NetworkBehaviourAction::CloseConnection {
                peer_id,
                connection,
            } => NetworkBehaviourAction::CloseConnection {
                peer_id,
                connection,
            },
        }
    }
}

/// The options w.r.t. which connection handler to notify of an event.
#[derive(Debug, Clone)]
pub enum NotifyHandler {
    /// Notify a particular connection handler.
    One(ConnectionId),
    /// Notify an arbitrary connection handler.
    Any,
}

/// The options which connections to close.
#[derive(Debug, Clone)]
pub enum CloseConnection {
    /// Disconnect a particular connection.
    One(ConnectionId),
    /// Disconnect all connections.
    All,
}

impl Default for CloseConnection {
    fn default() -> Self {
        CloseConnection::All
    }
}
