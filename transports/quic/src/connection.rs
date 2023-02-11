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

mod connecting;
mod substream;

pub use connecting::Connecting;
pub use substream::Substream;

use futures::{future::BoxFuture, FutureExt};
use libp2p_core::muxing::{StreamMuxer, StreamMuxerEvent};
use std::{
    pin::Pin,
    task::{Context, Poll},
};

/// State for a single opened QUIC connection.
pub struct Connection {
    connection: quinn::Connection,
    incoming:
        BoxFuture<'static, Result<(quinn::SendStream, quinn::RecvStream), quinn::ConnectionError>>,
    outgoing:
        BoxFuture<'static, Result<(quinn::SendStream, quinn::RecvStream), quinn::ConnectionError>>,
}

impl StreamMuxer for Connection {
    type Substream = Substream;
    type Error = quinn::ConnectionError;

    fn poll_inbound(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::Substream, Self::Error>> {
        let this = self.get_mut();

        let (send, recv) = futures::ready!(this.incoming.poll_unpin(cx))?;
        let connection = this.connection.clone();
        this.incoming = Box::pin(async move { connection.accept_bi().await });
        let substream = Substream::new(send, recv);
        Poll::Ready(Ok(substream))
    }

    fn poll_outbound(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::Substream, Self::Error>> {
        let this = self.get_mut();

        let (send, recv) = futures::ready!(this.outgoing.poll_unpin(cx))?;
        let connection = this.connection.clone();
        this.outgoing = Box::pin(async move { connection.open_bi().await });
        let substream = Substream::new(send, recv);
        Poll::Ready(Ok(substream))
    }

    fn poll(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<StreamMuxerEvent, Self::Error>> {
        Poll::Pending
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.connection.close(From::from(0u32), &[]);
        Poll::Ready(Ok(()))
    }
}
