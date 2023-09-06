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
    pub fn send(&self, data: T::NonOwning<'_>) -> Result<(), SendError<T>> {
        let owned = data.to_owned();
        self.inner_tx.send(owned)
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
}
