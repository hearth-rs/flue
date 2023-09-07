use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    ops::Deref,
    sync::Arc,
};

use parking_lot::Mutex;
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
            Signal::Unlink { address } => OwnedSignal::Unlink { address },
            Signal::Message { data, caps } => OwnedSignal::Message {
                data: data.to_vec(),
                caps: caps.to_vec(),
            },
        }
    }
}

enum OwnedSignal {
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
    links: Mutex<HashSet<Address>>,
    generation: u32,
}

impl Default for Route {
    fn default() -> Self {
        Self {
            tx: None,
            links: Mutex::new(HashSet::new()),
            generation: 0,
        }
    }
}

impl Clear for Route {
    fn clear(&mut self) {
        self.tx.take();
        self.links.lock().clear();
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

    pub(crate) fn kill(&self, address: &Address) {
        let Some(route) = self.get_route(address) else {
            return;
        };

        let links = route.links.lock();
        for link in links.iter() {
            self.send(&link, Signal::Unlink { address: *address });
        }

        self.routes.clear(address.handle);
    }

    pub(crate) fn link(&self, subject: &Address, object: &Address) {
        // shorthand to immediately unlink
        let unlink = move || {
            self.send(&object, Signal::Unlink { address: *subject });
            self.kill(&subject);
        };

        let Some(route) = self.get_route(subject) else {
            unlink();
            return;
        };

        let Some(tx) = &route.tx else {
            unlink();
            return;
        };

        if tx.receiver_count() == 0 {
            unlink();
            return;
        }

        route.links.lock().insert(*object);
    }

    pub(crate) fn send(&self, address: &Address, signal: Signal) {
        let Some(route) = self.get_route(address) else {
            return;
        };

        // fetch sender, if available
        let Some(tx) = &route.tx else {
            return;
        };

        // send signal
        let result = tx.send(signal);

        // kill this route if the receiver was dropped
        if result.is_err() {
            self.kill(address);
        }
    }

    fn get_route(&self, address: &Address) -> Option<impl Deref<Target = Route> + '_> {
        let route = self.routes.get(address.handle)?;

        if route.generation != address.generation {
            None
        } else {
            Some(route)
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

    pub fn spawn(&self) -> RefCell<Self> {
        Self::new_in(self.post.clone())
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

    pub(crate) fn map_signal<'a>(&mut self, signal: Signal<'a>) -> ContextSignal<'a> {
        match signal {
            Signal::Unlink { address } => ContextSignal::Unlink {
                handle: self.insert(Capability {
                    address,
                    perms: Permissions::empty(),
                }),
            },
            Signal::Message { data, caps } => ContextSignal::Message {
                data,
                caps: caps.iter().map(|cap| self.insert(*cap)).collect(),
            },
        }
    }

    pub fn import<'a>(&mut self, mailbox: &Mailbox<'a>, perms: Permissions) -> usize {
        let other = mailbox.table.borrow();
        assert_eq!(Arc::as_ptr(&self.post), Arc::as_ptr(&other.post));

        self.insert(Capability {
            address: mailbox.address,
            perms,
        })
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
        assert_eq!(mailbox.table.as_ptr(), self.table.as_ptr());

        let table = self.table.borrow();
        let entry = table.entries.get(self.handle).unwrap();
        table.post.link(&entry.cap.address, &mailbox.address);
    }

    pub fn send(&self, data: &[u8], caps: &[&TableAddress]) {
        let mut mapped_caps = Vec::with_capacity(caps.len());
        let table = self.table.borrow();
        for cap in caps.iter() {
            assert_eq!(cap.table.as_ptr(), self.table.as_ptr());
            let entry = table.entries.get(cap.handle).unwrap();
            mapped_caps.push(entry.cap);
        }

        self.signal(Signal::Message {
            data,
            caps: &mapped_caps,
        });
    }

    pub fn kill(&self) {
        let table = self.table.borrow();
        let entry = table.entries.get(self.handle).unwrap();
        table.post.kill(&entry.cap.address);
    }
}

pub struct Mailbox<'a> {
    table: &'a RefCell<Table>,
    address: Address,
    rx: Receiver<OwnedSignal>,
}

impl<'a> Drop for Mailbox<'a> {
    fn drop(&mut self) {
        let table = self.table.borrow();
        table.post.kill(&self.address);
    }
}

impl<'a> Mailbox<'a> {
    pub fn new(table: &'a RefCell<Table>) -> Self {
        let (tx, rx) = channel();
        let address = table.borrow().post.insert(tx);
        Self { table, address, rx }
    }

    pub async fn recv<T>(&mut self, mut f: impl FnMut(ContextSignal) -> T) -> Option<T> {
        self.rx
            .recv(|signal| {
                let mut table = self.table.borrow_mut();
                let signal = table.map_signal(signal);
                f(signal)
            })
            .await
            .ok()
    }

    pub fn try_recv<T>(&mut self, mut f: impl FnMut(ContextSignal) -> T) -> Option<Option<T>> {
        let result = self.rx.try_recv(|signal| {
            let mut table = self.table.borrow_mut();
            let signal = table.map_signal(signal);
            f(signal)
        });

        match result {
            Ok(t) => Some(Some(t)),
            Err(flume::TryRecvError::Empty) => Some(None),
            Err(flume::TryRecvError::Disconnected) => None,
        }
    }

    pub fn make_address(&self, perms: Permissions) -> TableAddress<'a> {
        let handle = self.table.borrow_mut().insert(Capability {
            address: self.address,
            perms,
        });

        TableAddress {
            table: self.table,
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
        assert_eq!(mb2.recv(|s| format!("{:?}", s)).await, None);
    }

    #[tokio::test]
    async fn unlink_on_kill() {
        let table = Table::new();
        let mut object = Mailbox::new(&table);

        let child = table.borrow().spawn();
        let s_mb = Mailbox::new(&child);

        let s_handle = table
            .borrow_mut()
            .import(&s_mb, Permissions::LINK | Permissions::KILL);

        let s_cap = TableAddress {
            table: &table,
            handle: s_handle,
        };

        s_cap.link(&object);
        s_cap.kill();

        let expected = ContextSignal::Unlink {
            handle: s_cap.demote(Permissions::empty()).handle,
        };

        object.recv(move |s| assert_eq!(s, expected)).await.unwrap();
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
        let table = Table::new();
        let mut object = Mailbox::new(&table);

        let child = table.borrow().spawn();
        let s_mb = Mailbox::new(&child);

        let s_handle = table
            .borrow_mut()
            .import(&s_mb, Permissions::LINK | Permissions::KILL);

        let s_cap = TableAddress {
            table: &table,
            handle: s_handle,
        };

        s_cap.kill();
        s_cap.link(&object);

        let expected = ContextSignal::Unlink {
            handle: s_cap.demote(Permissions::empty()).handle,
        };

        object.recv(move |s| assert_eq!(s, expected)).await.unwrap();
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
