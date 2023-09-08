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
    cell::RefCell,
    collections::{HashMap, HashSet},
    fmt::Debug,
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

struct RouteGroup {
    addresses: HashSet<Address>,
    dead: bool,
}

impl RouteGroup {
    pub fn kill(&mut self, post: &PostOffice) {
        if self.dead {
            return;
        }

        self.dead = true;

        for address in self.addresses.iter() {
            post.close(address);
        }
    }
}

struct Route {
    tx: Option<Sender<OwnedSignal>>,
    group: Option<Arc<Mutex<RouteGroup>>>,
    links: Mutex<HashSet<Address>>,
    generation: u32,
}

impl Default for Route {
    fn default() -> Self {
        Self {
            tx: None,
            group: None,
            links: Mutex::new(HashSet::new()),
            generation: 0,
        }
    }
}

impl Clear for Route {
    fn clear(&mut self) {
        self.tx.take();
        self.group.take();
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

    pub(crate) fn insert(&self, tx: Sender<OwnedSignal>, group: Arc<Mutex<RouteGroup>>) -> Address {
        let mut route = self.routes.create().unwrap();
        route.tx = Some(tx);
        route.group = Some(group);

        Address {
            handle: route.key(),
            generation: route.generation,
        }
    }

    pub(crate) fn kill(&self, address: &Address) {
        let Some(route) = self.get_route(address) else {
            return;
        };

        route.group.as_ref().unwrap().lock().kill(self);
    }

    pub(crate) fn close(&self, address: &Address) {
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
            self.close(&subject);
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

        // close this route if the receiver was dropped
        if result.is_err() {
            self.close(address);
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TableError {
    /// A handle used in this table operation was invalid.
    InvalidHandle,

    /// A handle used in this table operation does not have sufficient permissions.
    PermissionDenied,
}

#[derive(Debug)]
struct TableEntry {
    cap: Capability,
    refs: usize,
}

struct TableInner {
    entries: Slab<TableEntry>,
    reverse_entries: HashMap<Capability, usize>,
}

impl TableInner {
    pub fn insert(&mut self, cap: Capability) -> usize {
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
}

pub struct Table {
    post: Arc<PostOffice>,
    inner: RefCell<TableInner>,
}

impl Table {
    /// Creates a new [Table] in **a new [PostOffice]**.
    pub fn new() -> Self {
        let post = PostOffice::new();
        Self::new_in(post)
    }

    /// Creates a new [Table] in the same [PostOffice].
    pub fn spawn(&self) -> Self {
        Self::new_in(self.post.clone())
    }

    /// Creates a new [Table] in a specific [PostOffice].
    pub fn new_in(post: Arc<PostOffice>) -> Self {
        Self {
            post,
            inner: RefCell::new(TableInner {
                entries: Slab::new(),
                reverse_entries: HashMap::new(),
            }),
        }
    }

    pub(crate) fn insert(&self, cap: Capability) -> usize {
        self.inner.borrow_mut().insert(cap)
    }

    pub(crate) fn map_signal<'a>(&self, signal: Signal<'a>) -> ContextSignal<'a> {
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

    /// Tests if a raw capability handle is valid within this table.
    pub fn is_valid(&self, handle: usize) -> bool {
        self.inner.borrow().entries.contains(handle)
    }

    /// Wraps a raw capability handle in a Rust-friendly [CapabilityHandle] struct.
    pub fn wrap_handle(&self, handle: usize) -> Result<CapabilityHandle, TableError> {
        if !self.is_valid(handle) {
            return Err(TableError::InvalidHandle);
        }

        Ok(CapabilityHandle {
            table: self,
            handle,
        })
    }

    pub fn import<'a>(&self, mailbox: &Mailbox<'a>, perms: Permissions) -> usize {
        assert_eq!(
            Arc::as_ptr(&self.post),
            Arc::as_ptr(&mailbox.store.table.post)
        );

        self.insert(Capability {
            address: mailbox.address,
            perms,
        })
    }

    pub fn inc_ref(&self, handle: usize) -> Result<(), TableError> {
        self.inner
            .borrow_mut()
            .entries
            .get_mut(handle)
            .ok_or(TableError::InvalidHandle)?
            .refs += 1;

        Ok(())
    }

    pub fn dec_ref(&self, handle: usize) -> Result<(), TableError> {
        let mut inner = self.inner.borrow_mut();

        let entry = inner
            .entries
            .get_mut(handle)
            .ok_or(TableError::InvalidHandle)?;

        if entry.refs > 1 {
            entry.refs -= 1;
        } else {
            let entry = inner.entries.remove(handle);
            inner.reverse_entries.remove(&entry.cap);
        }

        Ok(())
    }

    pub fn get_permissions(&self, handle: usize) -> Result<Permissions, TableError> {
        self.inner
            .borrow()
            .entries
            .get(handle)
            .ok_or(TableError::InvalidHandle)
            .map(|e| e.cap.perms)
    }

    pub fn demote(&self, handle: usize, perms: Permissions) -> Result<usize, TableError> {
        let mut inner = self.inner.borrow_mut();
        let entry = inner.entries.get(handle).ok_or(TableError::InvalidHandle)?;
        let address = entry.cap.address;

        if !entry.cap.perms.contains(perms) {
            return Err(TableError::PermissionDenied);
        }

        let handle = inner.insert(Capability { address, perms });
        Ok(handle)
    }

    pub fn link(&self, handle: usize, mailbox: &Mailbox) -> Result<(), TableError> {
        assert!(std::ptr::eq(mailbox.store.table, self));
        let inner = self.inner.borrow();
        let entry = inner.entries.get(handle).ok_or(TableError::InvalidHandle)?;

        if !entry.cap.perms.contains(Permissions::LINK) {
            return Err(TableError::PermissionDenied);
        }

        self.post.link(&entry.cap.address, &mailbox.address);
        Ok(())
    }

    pub fn send(&self, handle: usize, data: &[u8], caps: &[usize]) -> Result<(), TableError> {
        let inner = self.inner.borrow();
        let entry = inner.entries.get(handle).ok_or(TableError::InvalidHandle)?;

        if !entry.cap.perms.contains(Permissions::SEND) {
            return Err(TableError::PermissionDenied);
        }

        let mut mapped_caps = Vec::with_capacity(caps.len());
        for cap in caps.iter() {
            let entry = inner.entries.get(*cap).ok_or(TableError::InvalidHandle)?;
            mapped_caps.push(entry.cap);
        }

        self.post.send(
            &entry.cap.address,
            Signal::Message {
                data,
                caps: &mapped_caps,
            },
        );

        Ok(())
    }

    pub fn kill(&self, handle: usize) -> Result<(), TableError> {
        let inner = self.inner.borrow();
        let entry = inner.entries.get(handle).ok_or(TableError::InvalidHandle)?;

        if !entry.cap.perms.contains(Permissions::KILL) {
            return Err(TableError::PermissionDenied);
        }

        self.post.kill(&entry.cap.address);
        Ok(())
    }
}

pub struct CapabilityHandle<'a> {
    table: &'a Table,
    handle: usize,
}

impl<'a> Clone for CapabilityHandle<'a> {
    fn clone(&self) -> Self {
        self.table.inc_ref(self.handle).unwrap();

        Self {
            table: self.table,
            handle: self.handle,
        }
    }
}

impl<'a> Debug for CapabilityHandle<'a> {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        fmt.debug_tuple("CapabilityHandle")
            .field(&self.handle)
            .finish()
    }
}

impl<'a> Drop for CapabilityHandle<'a> {
    fn drop(&mut self) {
        self.table.dec_ref(self.handle).unwrap();
    }
}

impl<'a> CapabilityHandle<'a> {
    /// Converts this handle wrapper into a raw handle index.
    ///
    /// You should call [Table::dec_ref] when you're done with this raw handle
    /// to avoid resource leaks.
    pub fn into_handle(self) -> usize {
        let handle = self.handle;
        std::mem::forget(self);
        handle
    }

    pub fn get_permissions(&self) -> Permissions {
        self.table.get_permissions(self.handle).unwrap()
    }

    pub fn demote(&self, perms: Permissions) -> Result<Self, TableError> {
        Ok(Self {
            table: self.table,
            handle: self.table.demote(self.handle, perms)?,
        })
    }

    pub fn link(&self, mailbox: &Mailbox<'a>) -> Result<(), TableError> {
        self.table.link(self.handle, mailbox)
    }

    pub fn send(&self, data: &[u8], caps: &[&CapabilityHandle]) -> Result<(), TableError> {
        let mut mapped_caps = Vec::with_capacity(caps.len());
        for cap in caps.iter() {
            assert!(std::ptr::eq(cap.table, self.table));
            mapped_caps.push(cap.handle);
        }

        self.table.send(self.handle, data, &mapped_caps)
    }

    pub fn kill(&self) -> Result<(), TableError> {
        self.table.kill(self.handle)
    }
}

pub struct MailboxStore<'a> {
    table: &'a Table,
    group: Arc<Mutex<RouteGroup>>,
}

impl<'a> MailboxStore<'a> {
    pub fn new(table: &'a Table) -> Self {
        Self {
            table,
            group: Arc::new(Mutex::new(RouteGroup {
                addresses: HashSet::new(),
                dead: false,
            })),
        }
    }

    pub fn create_mailbox(&self) -> Option<Mailbox<'_>> {
        let mut group = self.group.lock();

        if group.dead {
            return None;
        }

        let (tx, rx) = channel();
        let address = self.table.post.insert(tx, self.group.clone());
        group.addresses.insert(address);

        Some(Mailbox {
            store: self,
            address,
            rx,
        })
    }
}

pub struct Mailbox<'a> {
    store: &'a MailboxStore<'a>,
    address: Address,
    rx: Receiver<OwnedSignal>,
}

impl<'a> Drop for Mailbox<'a> {
    fn drop(&mut self) {
        self.store.table.post.close(&self.address);
    }
}

impl<'a> Mailbox<'a> {
    pub async fn recv<T>(&mut self, mut f: impl FnMut(ContextSignal) -> T) -> Option<T> {
        self.rx
            .recv(|signal| {
                let signal = self.store.table.map_signal(signal);
                f(signal)
            })
            .await
            .ok()
    }

    pub fn try_recv<T>(&mut self, mut f: impl FnMut(ContextSignal) -> T) -> Option<Option<T>> {
        let result = self.rx.try_recv(|signal| {
            let signal = self.store.table.map_signal(signal);
            f(signal)
        });

        match result {
            Ok(t) => Some(Some(t)),
            Err(flume::TryRecvError::Empty) => Some(None),
            Err(flume::TryRecvError::Disconnected) => None,
        }
    }

    pub fn make_capability(&self, perms: Permissions) -> CapabilityHandle<'a> {
        let handle = self.store.table.insert(Capability {
            address: self.address,
            perms,
        });

        CapabilityHandle {
            table: self.store.table,
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
        let mb_store = MailboxStore::new(&table);
        let mut mb = mb_store.create_mailbox().unwrap();
        let ad = mb.make_capability(Permissions::SEND);
        ad.send(b"Hello world!", &[]).unwrap();

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
        let mb_store = MailboxStore::new(&table);
        let mut mb = mb_store.create_mailbox().unwrap();
        let ad = mb.make_capability(Permissions::SEND);
        ad.send(b"", &[&ad]).unwrap();

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
    async fn try_recv() {
        let table = Table::new();
        let mb_store = MailboxStore::new(&table);
        let mut mb = mb_store.create_mailbox().unwrap();

        assert_eq!(mb.try_recv(|_| ()), Some(None));

        let ad = mb.make_capability(Permissions::SEND);
        ad.send(b"Hello world!", &[]).unwrap();

        assert!(mb
            .try_recv(|s| {
                s == ContextSignal::Message {
                    data: b"Hello world!",
                    caps: vec![],
                }
            })
            .unwrap()
            .unwrap());
    }

    #[tokio::test]
    async fn deny_send() {
        let table = Table::new();
        let mb_store = MailboxStore::new(&table);
        let mb = mb_store.create_mailbox().unwrap();
        let ad = mb.make_capability(Permissions::empty());
        let result = ad.send(b"", &[]);
        assert_eq!(result, Err(TableError::PermissionDenied));
    }

    #[tokio::test]
    async fn deny_kill() {
        let table = Table::new();
        let mb_store = MailboxStore::new(&table);
        let mb = mb_store.create_mailbox().unwrap();
        let ad = mb.make_capability(Permissions::empty());
        let result = ad.kill();
        assert_eq!(result, Err(TableError::PermissionDenied));
    }

    #[tokio::test]
    async fn deny_link() {
        let table = Table::new();
        let mb_store = MailboxStore::new(&table);
        let mb = mb_store.create_mailbox().unwrap();
        let ad = mb.make_capability(Permissions::empty());
        let result = ad.link(&mb);
        assert_eq!(result, Err(TableError::PermissionDenied));
    }

    #[tokio::test]
    async fn deny_demote_escalation() {
        let table = Table::new();
        let mb_store = MailboxStore::new(&table);
        let mb = mb_store.create_mailbox().unwrap();
        let ad = mb.make_capability(Permissions::KILL);
        let result = ad.demote(Permissions::SEND);
        assert_eq!(result.unwrap_err(), TableError::PermissionDenied);
    }

    #[tokio::test]
    async fn kill() {
        let table = Table::new();
        let mb_store = MailboxStore::new(&table);
        let mut mb = mb_store.create_mailbox().unwrap();
        let ad = mb.make_capability(Permissions::KILL);
        ad.kill().unwrap();
        assert_eq!(mb.recv(|s| format!("{:?}", s)).await, None);
    }

    #[tokio::test]
    async fn double_kill() {
        let table = Table::new();
        let mb_store = MailboxStore::new(&table);
        let mut mb = mb_store.create_mailbox().unwrap();
        let ad = mb.make_capability(Permissions::KILL);
        ad.kill().unwrap();
        ad.kill().unwrap();
        assert_eq!(mb.recv(|s| format!("{:?}", s)).await, None);
    }

    #[tokio::test]
    async fn dropped_handles_are_freed() {
        let table = Table::new();
        let mb_store = MailboxStore::new(&table);
        let mb = mb_store.create_mailbox().unwrap();
        let ad = mb.make_capability(Permissions::empty());
        let handle = ad.handle;
        assert!(table.is_valid(handle));
        drop(ad);
        assert!(!table.is_valid(handle));
    }

    #[tokio::test]
    async fn kill_all_mailboxes() {
        let table = Table::new();
        let mb_store = MailboxStore::new(&table);
        let mb1 = mb_store.create_mailbox().unwrap();
        let mut mb2 = mb_store.create_mailbox().unwrap();
        let ad = mb1.make_capability(Permissions::KILL);
        ad.kill().unwrap();
        assert_eq!(mb2.recv(|s| format!("{:?}", s)).await, None);
    }

    #[tokio::test]
    async fn unlink_on_kill() {
        let table = Table::new();
        let o_store = MailboxStore::new(&table);
        let mut object = o_store.create_mailbox().unwrap();

        let child = table.spawn();
        let s_store = MailboxStore::new(&child);
        let s_mb = s_store.create_mailbox().unwrap();

        let s_handle = table.import(&s_mb, Permissions::LINK | Permissions::KILL);

        let s_cap = CapabilityHandle {
            table: &table,
            handle: s_handle,
        };

        s_cap.link(&object).unwrap();
        s_cap.kill().unwrap();

        let expected = ContextSignal::Unlink {
            handle: s_cap.demote(Permissions::empty()).unwrap().handle,
        };

        object.recv(move |s| assert_eq!(s, expected)).await.unwrap();
    }

    #[tokio::test]
    async fn unlink_on_close() {
        let table = Table::new();
        let store = MailboxStore::new(&table);
        let s_mb = store.create_mailbox().unwrap();
        let s_cap = s_mb.make_capability(Permissions::LINK);
        let mut object = store.create_mailbox().unwrap();
        s_cap.link(&object).unwrap();
        drop(s_mb);

        let expected = ContextSignal::Unlink {
            handle: s_cap.demote(Permissions::empty()).unwrap().handle,
        };

        object.recv(move |s| assert_eq!(s, expected)).await.unwrap();
    }

    #[tokio::test]
    async fn unlink_dead() {
        let table = Table::new();
        let o_store = MailboxStore::new(&table);
        let mut object = o_store.create_mailbox().unwrap();

        let child = table.spawn();
        let s_store = MailboxStore::new(&child);
        let s_mb = s_store.create_mailbox().unwrap();

        let s_handle = table.import(&s_mb, Permissions::LINK | Permissions::KILL);

        let s_cap = CapabilityHandle {
            table: &table,
            handle: s_handle,
        };

        s_cap.kill().unwrap();
        s_cap.link(&object).unwrap();

        let expected = ContextSignal::Unlink {
            handle: s_cap.demote(Permissions::empty()).unwrap().handle,
        };

        object.recv(move |s| assert_eq!(s, expected)).await.unwrap();
    }

    #[tokio::test]
    async fn unlink_closed() {
        let table = Table::new();
        let store = MailboxStore::new(&table);
        let s_mb = store.create_mailbox().unwrap();
        let s_cap = s_mb.make_capability(Permissions::LINK);
        let mut object = store.create_mailbox().unwrap();
        drop(s_mb);
        s_cap.link(&object).unwrap();

        let expected = ContextSignal::Unlink {
            handle: s_cap.demote(Permissions::empty()).unwrap().handle,
        };

        object.recv(move |s| assert_eq!(s, expected)).await.unwrap();
    }
}
