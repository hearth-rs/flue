// Copyright (c) 2023 Marceline Cramer
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of Flue.
//
// Flue is free software: you can redistribute it and/or modify it under the
// terms of the GNU Affero General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// Flue is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
// details.
//
// You should have received a copy of the GNU Affero General Public License
// along with Flue. If not, see <https://www.gnu.org/licenses/>.

//! A zero-copy async SPSC channel for allocation-free signal-passing.

use std::{
    future::Future,
    marker::PhantomData,
    pin::Pin,
    task::{Context, Poll},
};

use flume::{RecvError, SendError, TryRecvError};

/// A message with a static lifetime that is queued in a zero-copy channel when
/// the receiver is not available to receive non-owning messages.
pub trait OwningMessage: 'static {
    /// The non-owning version of this message.
    type NonOwning<'a>: NonOwningMessage<'a, Owning = Self>;

    /// Convert this message to its non-owning version.
    fn to_non_owned(&self) -> Self::NonOwning<'_>;
}

/// A message with a generic lifetime that is immediately processed by a
/// zero-copy receiver if that receiver was available to receive non-owning
/// messages.
pub trait NonOwningMessage<'a> {
    /// The owning version of this message.
    type Owning: OwningMessage<NonOwning<'a> = Self>;

    /// Convert this message to its owning version.
    fn to_owned(self) -> Self::Owning;
}

/// A sender in a zero-copy channel.
pub struct Sender<T> {
    inner_tx: flume::Sender<T>,
}

impl<T> Sender<T>
where
    T: OwningMessage,
{
    /// Sends a non-owning message to the receiver in this channel.
    ///
    /// If the receiver is currently waiting for a message, the non-owning data
    /// will be sent as-is. Otherwise, the data is converted to its owned
    /// version and queued for later.
    pub fn send<'a>(&self, data: T::NonOwning<'a>) -> Result<SendFut<'a>, SendError<T>> {
        let owned = data.to_owned();
        self.inner_tx.send(owned)?;
        let fut = SendFut { _lock: PhantomData };
        Ok(fut)
    }

    /// The number of receivers in this channel.
    pub fn receiver_count(&self) -> usize {
        self.inner_tx.receiver_count()
    }
}

/// A future that waits for a non-owning message to finish being processed on
/// the receiving side. This is essential because this keeps a reference to the
/// message until the receiver is done with its memory and it can be
/// deallocated.
pub struct SendFut<'a> {
    _lock: PhantomData<&'a ()>,
}

impl<'a> Future for SendFut<'a> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Ready(())
    }
}

/// A receiver in a zero-copy channel.
pub struct Receiver<T> {
    inner_rx: flume::Receiver<T>,
}

impl<T> Receiver<T>
where
    T: OwningMessage,
{
    /// Receives a non-owning message from this channel.
    ///
    /// If there is a queued owning messaged, that message is immediately
    /// popped. Otherwise, this function waits for the sender to send
    /// non-owning data, which may be used directly.
    ///
    /// In order to preserve the safety of non-owning messages, the sender
    /// cannot finish sending a non-owning message until this function's
    /// closure has finished executing. **Exit the closure as quickly and as
    /// quickly as possible to avoid timing attack vulnerabilities.**
    pub async fn recv<R>(
        &self,
        mut f: impl for<'a> FnMut(T::NonOwning<'a>) -> R,
    ) -> Result<R, RecvError> {
        let owning = self.inner_rx.recv_async().await?;
        let non_owning = owning.to_non_owned();
        let result = f(non_owning);
        Ok(result)
    }

    /// Receives a queued owning message from this channel, if there is one.
    pub fn try_recv<R>(
        &self,
        mut f: impl for<'a> FnMut(T::NonOwning<'a>) -> R,
    ) -> Result<R, TryRecvError> {
        let owning = self.inner_rx.try_recv()?;
        let non_owning = owning.to_non_owned();
        let result = f(non_owning);
        Ok(result)
    }

    /// The number of senders in this channel.
    pub fn sender_count(&self) -> usize {
        self.inner_rx.sender_count()
    }
}

/// Creates a new zero-copy channel.
pub fn channel<T>() -> (Sender<T>, Receiver<T>) {
    let (inner_tx, inner_rx) = flume::unbounded();
    (Sender { inner_tx }, Receiver { inner_rx })
}

#[cfg(test)]
mod tests {
    use super::*;

    impl OwningMessage for String {
        type NonOwning<'a> = &'a str;

        fn to_non_owned(&self) -> Self::NonOwning<'_> {
            self.as_str()
        }
    }

    impl<'a> NonOwningMessage<'a> for &'a str {
        type Owning = String;

        fn to_owned(self) -> Self::Owning {
            self.to_string()
        }
    }

    #[tokio::test]
    async fn alias_sent_on_pending_recv() {
        let (tx, rx) = channel::<String>();
        let sent = "shared string";
        let test = |received: &str| sent.as_ptr() == received.as_ptr();
        let join_rx = tokio::spawn(async move { rx.recv(test).await });
        tx.send(sent).unwrap().await;
        assert!(join_rx.await.unwrap().unwrap());
    }
}
