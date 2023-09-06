use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    sync::Arc,
};

use sharded_slab::Slab as ShardedSlab;
use slab::Slab;
use zerocopy::{channel, NonOwningMessage, OwningMessage, Receiver, Sender};

pub mod zerocopy;

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct Permissions: u32 {
        const SEND = 1 << 0;
        const LINK = 1 << 1;
        const KILL = 1 << 2;
    }
}

enum Signal<'a> {
    Kill,
    Link { handle: usize },
    Unlink { handle: usize },
    Message { data: &'a [u8], caps: &'a [usize] },
}

impl<'a> NonOwningMessage<'a> for Signal<'a> {
    type Owning = OwnedSignal;

    fn to_owned(self) -> OwnedSignal {
        match self {
            Signal::Kill => OwnedSignal::Kill,
            Signal::Link { handle } => OwnedSignal::Link { handle },
            Signal::Unlink { handle } => OwnedSignal::Unlink { handle },
            Signal::Message { data, caps } => OwnedSignal::Message {
                data: data.to_vec(),
                caps: caps.to_vec(),
            },
        }
    }
}

enum OwnedSignal {
    Kill,
    Link { handle: usize },
    Unlink { handle: usize },
    Message { data: Vec<u8>, caps: Vec<usize> },
}

impl OwningMessage for OwnedSignal {
    type NonOwning<'a> = Signal<'a>;

    fn to_non_owned(&self) -> Self::NonOwning<'_> {
        match self {
            OwnedSignal::Kill => Signal::Kill,
            OwnedSignal::Link { handle } => Signal::Link { handle: *handle },
            OwnedSignal::Unlink { handle } => Signal::Unlink { handle: *handle },
            OwnedSignal::Message { data, caps } => Signal::Message {
                data: data.as_slice(),
                caps: caps.as_slice(),
            },
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContextSignal<'a> {
    Unlink { handle: usize },
    Message { data: &'a [u8], caps: Vec<usize> },
}

struct Route {
    tx: Sender<OwnedSignal>,
}

pub struct PostOffice {
    routes: ShardedSlab<Route>,
}

impl PostOffice {
    pub fn new() -> Self {
        Self {
            routes: ShardedSlab::new(),
        }
    }

    pub(crate) fn insert(&self, route: Route) -> usize {
        self.routes.insert(route).unwrap()
    }

    pub(crate) fn send(&self, handle: usize, signal: Signal) {
        let _ = self.routes.get(handle).unwrap().tx.send(signal);
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct Address {
    pub handle: usize,
    pub perms: Permissions,
}

#[derive(Clone, Copy)]
pub struct AddressRef<'a> {
    post: &'a Arc<PostOffice>,
    inner: Address,
}

pub struct AddressOwned {
    post: Arc<PostOffice>,
    inner: Address,
}

impl AddressOwned {
    pub fn as_ref(&self) -> AddressRef<'_> {
        AddressRef {
            post: &self.post,
            inner: self.inner,
        }
    }
}

struct TableEntry {
    address: Address,
    refs: usize,
}

pub struct Table<'a> {
    post: &'a PostOffice,
    entries: Slab<TableEntry>,
    reverse_entries: HashMap<Address, usize>,
}

impl<'a> Table<'a> {
    pub(crate) fn new(post: &'a PostOffice) -> RefCell<Self> {
        RefCell::new(Self {
            post,
            entries: Slab::new(),
            reverse_entries: HashMap::new(),
        })
    }

    pub(crate) fn insert(&mut self, address: Address) -> usize {
        use std::collections::hash_map::Entry;
        let entry = self.reverse_entries.entry(address);
        match entry {
            Entry::Occupied(handle) => {
                let handle = *handle.get();
                self.entries.get_mut(handle).unwrap().refs += 1;
                handle
            }
            Entry::Vacant(reverse_entry) => {
                let refs = 1;
                let entry = TableEntry { address, refs };
                let handle = self.entries.insert(entry);
                reverse_entry.insert(handle);
                handle
            }
        }
    }

    pub fn inc_ref(&mut self, handle: usize) {
        self.entries.get_mut(handle).unwrap().refs += 1;
    }

    pub fn dec_ref(&mut self, handle: usize) {
        let entry = self.entries.get_mut(handle).unwrap();
        if entry.refs <= 1 {
            entry.refs -= 1;
        } else {
            self.entries.remove(handle);
        }
    }
}

pub struct TableAddress<'a> {
    table: &'a RefCell<Table<'a>>,
    handle: usize,
}

impl<'a> Clone for TableAddress<'a> {
    fn clone(&self) -> Self {
        self.table.borrow_mut().inc_ref(self.handle);

        Self {
            table: self.table,
            handle: self.handle,
        }
    }
}

impl<'a> Drop for TableAddress<'a> {
    fn drop(&mut self) {
        self.table.borrow_mut().dec_ref(self.handle);
    }
}

impl<'a> TableAddress<'a> {
    pub(crate) fn signal(&self, signal: Signal) {
        let table = self.table.borrow();
        let entry = table.entries.get(self.handle).unwrap();
        table.post.send(entry.address.handle, signal);
    }

    pub fn send(&self, data: &[u8], _caps: &[&TableAddress]) {
        self.signal(Signal::Message { data, caps: &[] });
    }

    pub fn kill(&self) {
        self.signal(Signal::Kill);
    }
}

pub struct LinkTable<'a> {
    handle: usize,
    table: &'a RefCell<Table<'a>>,
    linked: HashSet<usize>,
}

impl<'a> Drop for LinkTable<'a> {
    fn drop(&mut self) {
        let table = self.table.borrow();
        for link in self.linked.drain() {
            table.post.send(
                link,
                Signal::Unlink {
                    handle: self.handle,
                },
            );
        }
    }
}

impl<'a> LinkTable<'a> {
    pub(crate) fn new(table: &'a RefCell<Table<'a>>, handle: usize) -> Self {
        Self {
            handle,
            table,
            linked: HashSet::new(),
        }
    }

    pub(crate) fn on_signal<'s>(&mut self, signal: Signal<'s>) -> Result<ContextSignal<'s>, bool> {
        let ctx_signal = match signal {
            Signal::Kill => return Err(false),
            Signal::Link { handle } => {
                self.linked.insert(handle);
                return Err(true);
            }
            Signal::Unlink { handle } => ContextSignal::Unlink { handle },
            Signal::Message { data, caps } => ContextSignal::Message {
                data,
                caps: self.map_caps(caps),
            },
        };

        Ok(ctx_signal)
    }

    pub(crate) fn map_caps(&self, caps: &[usize]) -> Vec<usize> {
        let mut table = self.table.borrow_mut();

        caps.iter()
            .map(|cap| {
                table.insert(Address {
                    handle: *cap,
                    perms: Permissions::empty(),
                })
            })
            .collect()
    }
}

pub struct Mailbox<'a> {
    handle: usize,
    linked: LinkTable<'a>,
    rx: Receiver<OwnedSignal>,
}

impl<'a> Mailbox<'a> {
    pub fn new(table: &'a RefCell<Table<'a>>) -> Self {
        let (tx, rx) = channel();
        let route = Route { tx };
        let handle = table.borrow().post.insert(route);

        Self {
            handle,
            linked: LinkTable::new(table, handle),
            rx,
        }
    }

    pub async fn recv<T>(&mut self, mut f: impl FnMut(ContextSignal) -> T) -> Option<T> {
        loop {
            let (rx, linked) = (&self.rx, &mut self.linked);
            let result = rx
                .recv(|signal| linked.on_signal(signal).map(|ctx_signal| f(ctx_signal)))
                .await;

            match result {
                Ok(Ok(signal)) => break Some(signal),
                Ok(Err(false)) => break None,
                _ => {}
            }
        }
    }

    pub fn try_recv<T>(&mut self, mut f: impl FnMut(ContextSignal) -> T) -> Option<Option<T>> {
        loop {
            let (rx, linked) = (&self.rx, &mut self.linked);
            let result =
                rx.try_recv(|signal| linked.on_signal(signal).map(|ctx_signal| f(ctx_signal)));

            match result {
                Ok(Ok(signal)) => break Some(Some(signal)),
                Ok(Err(false)) => break None,
                Err(_) => break Some(None),
                _ => {}
            }
        }
    }

    pub fn make_address(&self, perms: Permissions) -> TableAddress<'a> {
        let handle = self.linked.table.borrow_mut().insert(Address {
            handle: self.handle,
            perms,
        });

        TableAddress {
            table: self.linked.table,
            handle,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn send_message() {
        let post = Arc::new(PostOffice::new());
        let table = Table::new(post.as_ref());
        let mut mb = Mailbox::new(&table);
        let ad = mb.make_address(Permissions::SEND);
        ad.send(b"Hello world!", &[]);

        assert!(mb
            .recv(|s| {
                s == ContextSignal::Message {
                    data: b"Hello world!",
                    caps: vec![],
                }
            })
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn send_address() {
        let post = Arc::new(PostOffice::new());
        let table = Table::new(post.as_ref());
        let mut mb = Mailbox::new(&table);
        let ad = mb.make_address(Permissions::SEND);
        ad.send(b"", &[&ad]);

        assert!(mb
            .recv(move |s| {
                s == ContextSignal::Message {
                    data: b"",
                    caps: vec![ad.handle],
                }
            })
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn kill() {
        let post = Arc::new(PostOffice::new());
        let table = Table::new(post.as_ref());
        let mut mb = Mailbox::new(&table);
        let ad = mb.make_address(Permissions::KILL);
        ad.kill();
        assert_eq!(mb.recv(|s| format!("{:?}", s)).await, None);
    }

    #[tokio::test]
    async fn kill_all_mailboxes() {
        let post = Arc::new(PostOffice::new());
        let table = Table::new(post.as_ref());
        let mb1 = Mailbox::new(&table);
        let mut mb2 = Mailbox::new(&table);
        let ad = mb1.make_address(Permissions::KILL);
        ad.kill();
        assert_eq!(mb2.try_recv(|s| format!("{:?}", s)), None);
    }
}
