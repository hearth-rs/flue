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

use std::{
    future::Future,
    marker::PhantomData,
    pin::Pin,
    task::{Context, Poll},
};

use flume::{RecvError, SendError, TryRecvError};

pub trait OwningMessage: 'static {
    type NonOwning<'a>: NonOwningMessage<'a, Owning = Self>;
    fn to_non_owned(&self) -> Self::NonOwning<'_>;
}

pub trait NonOwningMessage<'a> {
    type Owning: OwningMessage<NonOwning<'a> = Self>;
    fn to_owned(self) -> Self::Owning;
}

pub struct Sender<T> {
    inner_tx: flume::Sender<T>,
}

impl<T> Sender<T>
where
    T: OwningMessage,
{
    pub fn send<'a>(&self, data: T::NonOwning<'a>) -> Result<SendFut<'a>, SendError<T>> {
        let owned = data.to_owned();
        self.inner_tx.send(owned)?;
        let fut = SendFut { _lock: PhantomData };
        Ok(fut)
    }

    pub fn receiver_count(&self) -> usize {
        self.inner_tx.receiver_count()
    }
}

pub struct SendFut<'a> {
    _lock: PhantomData<&'a ()>,
}

impl<'a> Future for SendFut<'a> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Ready(())
    }
}

pub struct Receiver<T> {
    inner_rx: flume::Receiver<T>,
}

impl<T> Receiver<T>
where
    T: OwningMessage,
{
    pub async fn recv<R>(
        &self,
        mut f: impl for<'a> FnMut(T::NonOwning<'a>) -> R,
    ) -> Result<R, RecvError> {
        let owning = self.inner_rx.recv_async().await?;
        let non_owning = owning.to_non_owned();
        let result = f(non_owning);
        Ok(result)
    }

    pub fn try_recv<R>(
        &self,
        mut f: impl for<'a> FnMut(T::NonOwning<'a>) -> R,
    ) -> Result<R, TryRecvError> {
        let owning = self.inner_rx.try_recv()?;
        let non_owning = owning.to_non_owned();
        let result = f(non_owning);
        Ok(result)
    }

    pub fn sender_count(&self) -> usize {
        self.inner_rx.sender_count()
    }
}

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
