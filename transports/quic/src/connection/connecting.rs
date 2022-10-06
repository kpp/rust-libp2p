// Copyright 2017-2020 Parity Technologies (UK) Ltd.
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

use crate::Connection;
use crate::{connection::Event, connection::State, transport};
use futures::{prelude::*};
use futures_timer::Delay;
use libp2p_core::PeerId;
use std::{
    pin::Pin,
    task::{Context, Poll},
};
use std::time::Duration;

/// Future that drives a QUIC connection until is has performed its TLS handshake.
#[derive(Debug)]
pub struct Connecting {
    state: Option<State>,
    timeout: Delay,
}

impl Connecting {
    pub(crate) fn new(state: State, timeout: Duration) -> Self {
        Connecting {
            state: Some(state),
            timeout: Delay::new(timeout),
        }
    }
}

impl Future for Connecting {
    type Output = Result<(PeerId, Connection), transport::TransportError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let state = self
            .state
            .as_mut()
            .expect("Future polled after it has completed");

        loop {
            match state.poll_event(cx) {
                Poll::Ready(Event::Connected(peer_id)) => {
                    let muxer = Connection::new(self.state.take().unwrap());
                    return Poll::Ready(Ok((peer_id, muxer)));
                }
                Poll::Ready(Event::ConnectionLost(err)) => return Poll::Ready(Err(err.into())),
                Poll::Ready(Event::HandshakeDataReady)
                | Poll::Ready(Event::StreamAvailable)
                | Poll::Ready(Event::StreamOpened)
                | Poll::Ready(Event::StreamReadable(_))
                | Poll::Ready(Event::StreamWritable(_))
                | Poll::Ready(Event::StreamFinished(_))
                | Poll::Ready(Event::StreamStopped(_)) => continue,
                Poll::Pending => {}
            }

            match self.timeout.poll_unpin(cx) {
                Poll::Ready(()) => {
                    return Poll::Ready(Err(transport::TransportError::HandshakeTimedOut))
                }
                Poll::Pending => {}
            }
            return Poll::Pending;
        }
    }
}
