use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    sync::Arc,
};

use sharded_slab::{Clear, Pool};
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

#[derive(Clone, Copy, Debug)]
enum Signal<'a> {
    Kill,
    Link {
        address: Address,
    },
    Unlink {
        address: Address,
    },
    Message {
        data: &'a [u8],
        caps: &'a [Capability],
    },
}

impl<'a> NonOwningMessage<'a> for Signal<'a> {
    type Owning = OwnedSignal;

    fn to_owned(self) -> OwnedSignal {
        match self {
            Signal::Kill => OwnedSignal::Kill,
            Signal::Link { address } => OwnedSignal::Link { address },
            Signal::Unlink { address } => OwnedSignal::Unlink { address },
            Signal::Message { data, caps } => OwnedSignal::Message {
                data: data.to_vec(),
                caps: caps.to_vec(),
            },
        }
    }
}

enum OwnedSignal {
    Kill,
    Link {
        address: Address,
    },
    Unlink {
        address: Address,
    },
    Message {
        data: Vec<u8>,
        caps: Vec<Capability>,
    },
}

impl OwningMessage for OwnedSignal {
    type NonOwning<'a> = Signal<'a>;

    fn to_non_owned(&self) -> Self::NonOwning<'_> {
        match self {
            OwnedSignal::Kill => Signal::Kill,
            OwnedSignal::Link { address } => Signal::Link { address: *address },
            OwnedSignal::Unlink { address } => Signal::Unlink { address: *address },
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
    tx: Option<Sender<OwnedSignal>>,
    generation: u32,
}

impl Default for Route {
    fn default() -> Self {
        Self {
            tx: None,
            generation: 0,
        }
    }
}

impl Clear for Route {
    fn clear(&mut self) {
        self.tx.take();
        self.generation += 1;
    }
}

pub struct PostOffice {
    routes: Pool<Route>,
}

impl PostOffice {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            routes: Pool::new(),
        })
    }

    pub(crate) fn insert(&self, tx: Sender<OwnedSignal>) -> Address {
        let mut route = self.routes.create().unwrap();
        route.tx = Some(tx);

        Address {
            handle: route.key(),
            generation: route.generation,
        }
    }

    pub(crate) fn send(&self, address: &Address, signal: Signal) {
        let route = self.routes.get(address.handle).unwrap();

        // shorthand to immediately unlink
        let unlink = move || {
            if let Signal::Link { address: reply } = signal {
                self.send(&reply, Signal::Unlink { address: *address });
            }
        };

        // check that generation is valid
        if route.generation != address.generation {
            unlink();
            return;
        }

        // fetch sender, if available
        let Some(tx) = &route.tx else {
            unlink();
            return;
        };

        // send signal
        let result = tx.send(signal);

        // clear this route if the receiver was dropped
        if result.is_err() {
            unlink();
            self.routes.clear(address.handle);
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Address {
    pub handle: usize,
    pub generation: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Capability {
    pub address: Address,
    pub perms: Permissions,
}

#[derive(Debug)]
struct TableEntry {
    cap: Capability,
    refs: usize,
}

pub struct Table {
    post: Arc<PostOffice>,
    entries: Slab<TableEntry>,
    reverse_entries: HashMap<Capability, usize>,
}

impl Table {
    pub fn new() -> RefCell<Self> {
        let post = PostOffice::new();
        Self::new_in(post)
    }

    pub(crate) fn new_in(post: Arc<PostOffice>) -> RefCell<Self> {
        RefCell::new(Self {
            post,
            entries: Slab::new(),
            reverse_entries: HashMap::new(),
        })
    }

    pub(crate) fn insert(&mut self, cap: Capability) -> usize {
        use std::collections::hash_map::Entry;
        let entry = self.reverse_entries.entry(cap);
        match entry {
            Entry::Occupied(handle) => {
                let handle = *handle.get();
                self.entries.get_mut(handle).unwrap().refs += 1;
                handle
            }
            Entry::Vacant(reverse_entry) => {
                let refs = 1;
                let entry = TableEntry { cap, refs };
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
    table: &'a RefCell<Table>,
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
    pub fn demote(&self, perms: Permissions) -> Self {
        let mut table = self.table.borrow_mut();
        let entry = table.entries.get(self.handle).unwrap();
        let address = entry.cap.address;
        let handle = table.insert(Capability { address, perms });

        Self {
            table: self.table,
            handle,
        }
    }

    pub(crate) fn signal(&self, signal: Signal) {
        let table = self.table.borrow();
        let entry = table.entries.get(self.handle).unwrap();
        table.post.send(&entry.cap.address, signal);
    }

    pub fn link(&self, mailbox: &Mailbox<'a>) {
        assert_eq!(mailbox.linked.table.as_ptr(), self.table.as_ptr());

        self.signal(Signal::Link {
            address: mailbox.address,
        });
    }

    pub fn send(&self, data: &[u8], caps: &[&TableAddress]) {
        self.signal(Signal::Message { data, caps: &[] });
    }

    pub fn kill(&self) {
        self.signal(Signal::Kill);
    }
}

pub struct LinkTable<'a> {
    address: Address,
    table: &'a RefCell<Table>,
    linked: HashSet<Address>,
}

impl<'a> Drop for LinkTable<'a> {
    fn drop(&mut self) {
        let table = self.table.borrow();
        let address = self.address;
        for link in self.linked.drain() {
            table.post.send(&link, Signal::Unlink { address });
        }
    }
}

impl<'a> LinkTable<'a> {
    pub(crate) fn new(table: &'a RefCell<Table>, address: Address) -> Self {
        Self {
            address,
            table,
            linked: HashSet::new(),
        }
    }

    pub(crate) fn on_signal<'s>(&mut self, signal: Signal<'s>) -> Result<ContextSignal<'s>, bool> {
        let ctx_signal = match signal {
            Signal::Kill => return Err(false),
            Signal::Link { address } => {
                self.linked.insert(address);
                return Err(true);
            }
            Signal::Unlink { address } => ContextSignal::Unlink {
                handle: self.table.borrow_mut().insert(Capability {
                    address,
                    perms: Permissions::empty(),
                }),
            },
            Signal::Message { data, caps } => ContextSignal::Message {
                data,
                caps: self.map_caps(caps),
            },
        };

        Ok(ctx_signal)
    }

    pub(crate) fn map_caps(&self, caps: &[Capability]) -> Vec<usize> {
        let mut table = self.table.borrow_mut();
        caps.iter().map(|cap| table.insert(*cap)).collect()
    }
}

pub struct Mailbox<'a> {
    address: Address,
    linked: LinkTable<'a>,
    rx: Receiver<OwnedSignal>,
}

impl<'a> Drop for Mailbox<'a> {
    fn drop(&mut self) {
        // flush and process messages
        while let Some(Some(_)) = self.try_recv(|_| ()) {}
    }
}

impl<'a> Mailbox<'a> {
    pub fn new(table: &'a RefCell<Table>) -> Self {
        let (tx, rx) = channel();
        let address = table.borrow().post.insert(tx);

        Self {
            address,
            linked: LinkTable::new(table, address),
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
        let handle = self.linked.table.borrow_mut().insert(Capability {
            address: self.address,
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
        let table = Table::new();
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
        let table = Table::new();
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
        let table = Table::new();
        let mut mb = Mailbox::new(&table);
        let ad = mb.make_address(Permissions::KILL);
        ad.kill();
        assert_eq!(mb.recv(|s| format!("{:?}", s)).await, None);
    }

    #[tokio::test]
    async fn kill_all_mailboxes() {
        let table = Table::new();
        let mb1 = Mailbox::new(&table);
        let mut mb2 = Mailbox::new(&table);
        let ad = mb1.make_address(Permissions::KILL);
        ad.kill();
        assert_eq!(mb2.try_recv(|s| format!("{:?}", s)), None);
    }

    #[tokio::test]
    async fn unlink_on_kill() {
        todo!();
    }

    #[tokio::test]
    async fn unlink_on_close() {
        let table = Table::new();
        let s_mb = Mailbox::new(&table);
        let s_cap = s_mb.make_address(Permissions::LINK);
        let mut object = Mailbox::new(&table);
        s_cap.link(&object);
        drop(s_mb);

        let expected = ContextSignal::Unlink {
            handle: s_cap.demote(Permissions::empty()).handle,
        };

        object.recv(move |s| assert_eq!(s, expected)).await.unwrap();
    }

    #[tokio::test]
    async fn unlink_dead() {
        todo!();
    }

    #[tokio::test]
    async fn unlink_closed() {
        let table = Table::new();
        let s_mb = Mailbox::new(&table);
        let s_cap = s_mb.make_address(Permissions::LINK);
        let mut object = Mailbox::new(&table);
        drop(s_mb);
        s_cap.link(&object);

        let expected = ContextSignal::Unlink {
            handle: s_cap.demote(Permissions::empty()).handle,
        };

        object.recv(move |s| assert_eq!(s, expected)).await.unwrap();
    }
}
