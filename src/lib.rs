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
    collections::{HashMap, HashSet},
    fmt::{Debug, Display},
    ops::Deref,
    sync::Arc,
};

use parking_lot::Mutex;
use sharded_slab::{Clear, Pool};
use slab::Slab;
use zerocopy::{channel, NonOwningMessage, OwningMessage, Receiver, Sender};

pub mod zerocopy;

bitflags::bitflags! {
    /// Permission flags for a capability.
    ///
    /// These gate access to fundamental route operations. When choosing the
    /// permissions for a capability, please follow the principle of least
    /// privilege for sharing capability access.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct Permissions: u32 {
        /// The permission to send messages to this capability.
        const SEND = 1 << 0;

        /// The permission to link to this capability and be notified of its
        /// closure.
        const LINK = 1 << 1;

        /// The permission to kill this capability.
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

struct RouteGroup {
    addresses: HashSet<Address>,
    dead: bool,
}

impl RouteGroup {
    pub fn kill(&mut self, post: &Arc<PostOffice>) {
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

/// Shared signal transport for all of the processes in a shared context.
///
/// Instantiate one [PostOffice] per collection of interoperating processes,
/// and use it in [Table::new] to create a new capability table.
pub struct PostOffice {
    routes: Pool<Route>,
}

impl PostOffice {
    /// Creates a new post office.
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

    pub(crate) fn kill(self: &Arc<Self>, address: &Address) {
        let Some(route) = self.get_route(address) else {
            return;
        };

        route.group.as_ref().unwrap().lock().kill(self);
    }

    pub(crate) fn close(self: &Arc<Self>, address: &Address) {
        let Some(route) = self.get_route(address) else {
            return;
        };

        let address = *address;
        let links = route.links.lock().to_owned();
        let post = self.to_owned();

        tokio::spawn(async move {
            for link in links {
                post.send(&link, Signal::Unlink { address }).await;
            }
        });

        self.routes.clear(address.handle);
    }

    pub(crate) async fn send(self: &Arc<Self>, address: &Address, signal: Signal<'_>) {
        let result = {
            let Some(route) = self.get_route(address) else {
                return;
            };

            // fetch sender, if available
            let Some(tx) = &route.tx else {
                return;
            };

            // send signal
            let result = tx.send(signal);

            result
        };

        // close this route if the receiver was dropped
        let fut = if let Ok(fut) = result {
            fut
        } else {
            self.close(address);
            return;
        };

        // wait for send to complete
        fut.await;
    }

    pub(crate) fn link(self: &Arc<Self>, subject: &Address, object: &Address) {
        // shorthand to immediately unlink
        let unlink = || {
            let subject = *subject;
            let object = *object;
            let post = self.to_owned();
            tokio::spawn(async move {
                post.send(&object, Signal::Unlink { address: subject })
                    .await;
                post.close(&subject);
            })
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

/// A freestanding capability that is not tied to any [Table].
///
/// This can be used to conveniently transfer single capabilities from one
/// table to another without needing to send and receive messages.
///
/// You can get and insert owned capabilities using [Table::get_owned] and
/// [Table::insert_owned]. Please keep in mind that owned capabilities have
/// an `Arc<PostOffice>` inside and are thus relatively expensive to clone and
/// destroy. Minimize their usage in performance-critical code.
#[derive(Clone)]
pub struct OwnedCapability {
    inner: Capability,
    post: Arc<PostOffice>,
}

/// An error in performing a capability operation in a [Table].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TableError {
    /// A handle used in this table operation was invalid.
    InvalidHandle,

    /// A handle used in this table operation does not have sufficient permissions.
    PermissionDenied,
}

impl Display for TableError {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            TableError::InvalidHandle => write!(fmt, "invalid handle"),
            TableError::PermissionDenied => write!(fmt, "permission denied"),
        }
    }
}

impl std::error::Error for TableError {}

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

/// Contains unforgeable capabilities, performs operations on them, and moderates
/// access to them.
///
/// Each capability in a [Table] is referenced by an opaque integer handle.
/// Handles are reference-counted, and are freed when their refcount hits zero.
///
/// This struct has low-level operations on capability handles, but unless
/// you're doing low-level integration of a table into a scripting environment,
/// you probably want to use [CapabilityHandle] instead, which provides some
/// higher-level abstraction for handle ownership.
///
/// All incoming capabilities to this table are mapped to handles, and identical
/// capabilities are given owning references to the same handle. If two handles
/// have the same integer value, then they are identical. Please note that
/// the equivalence of capabilities is determined by both that capability's
/// address (the route it actually points to) **AND** its [Permissions]. Two
/// capabilities can point to the same route but be unequivalent because they
/// have different permissions, so proceed with caution.
pub struct Table {
    post: Arc<PostOffice>,
    inner: Mutex<TableInner>,
}

impl Default for Table {
    fn default() -> Self {
        let post = PostOffice::new();
        Self::new(post)
    }
}

impl Table {
    /// Creates a new [Table] in a [PostOffice].
    pub fn new(post: Arc<PostOffice>) -> Self {
        Self {
            post,
            inner: Mutex::new(TableInner {
                entries: Slab::new(),
                reverse_entries: HashMap::new(),
            }),
        }
    }

    /// Creates a new [Table] in the same [PostOffice].
    pub fn spawn(&self) -> Self {
        Self::new(self.post.clone())
    }

    /// Gets an [OwnedCapability] by handle.
    pub fn get_owned(&self, handle: usize) -> Result<OwnedCapability, TableError> {
        let inner = self
            .inner
            .lock()
            .entries
            .get(handle)
            .ok_or(TableError::InvalidHandle)?
            .cap;

        let post = self.post.clone();

        Ok(OwnedCapability { inner, post })
    }

    /// Directly inserts an [OwnedCapability] into this table.
    pub fn insert_owned(&self, cap: OwnedCapability) -> Result<usize, TableError> {
        assert_eq!(Arc::as_ptr(&self.post), Arc::as_ptr(&cap.post));
        Ok(self.insert(cap.inner))
    }

    pub(crate) fn insert(&self, cap: Capability) -> usize {
        self.inner.lock().insert(cap)
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

    pub(crate) fn map_signal_owned(&self, signal: Signal<'_>) -> OwnedContextSignal<'_> {
        match self.map_signal(signal) {
            ContextSignal::Unlink { handle } => OwnedContextSignal::Unlink {
                handle: self.wrap_handle(handle).unwrap(),
            },
            ContextSignal::Message { data, caps } => OwnedContextSignal::Message {
                data: data.to_owned(),
                caps: caps
                    .into_iter()
                    .map(|cap| self.wrap_handle(cap).unwrap())
                    .collect(),
            },
        }
    }

    /// Tests if a raw capability handle is valid within this table.
    pub fn is_valid(&self, handle: usize) -> bool {
        self.inner.lock().entries.contains(handle)
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

    /// Imports a capability to *any* [Mailbox] into this table.
    ///
    /// Panics if the mailbox has a different [PostOffice].
    pub fn import(&self, mailbox: &Mailbox, perms: Permissions) -> usize {
        assert_eq!(
            Arc::as_ptr(&self.post),
            Arc::as_ptr(&mailbox.store.table.post)
        );

        self.insert(Capability {
            address: mailbox.address,
            perms,
        })
    }

    /// Increments the reference count of a capability handle.
    ///
    /// If you'd prefer not to do this manually, try using [Table::wrap_handle]
    /// and relying on [CapabilityHandle]'s `Clone` implementation instead.
    pub fn inc_ref(&self, handle: usize) -> Result<(), TableError> {
        self.inner
            .lock()
            .entries
            .get_mut(handle)
            .ok_or(TableError::InvalidHandle)?
            .refs += 1;

        Ok(())
    }

    /// Decrements the reference count of a capability handle. Removes this
    /// capability from this table if the reference count hits zero.
    ///
    /// If you'd prefer not to do this manually, try using [Table::wrap_handle]
    /// and relying on [CapabilityHandle]'s `Drop` implementation instead.
    pub fn dec_ref(&self, handle: usize) -> Result<(), TableError> {
        let mut inner = self.inner.lock();

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
            .lock()
            .entries
            .get(handle)
            .ok_or(TableError::InvalidHandle)
            .map(|e| e.cap.perms)
    }

    pub fn demote(&self, handle: usize, perms: Permissions) -> Result<usize, TableError> {
        let mut inner = self.inner.lock();
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
        let inner = self.inner.lock();
        let entry = inner.entries.get(handle).ok_or(TableError::InvalidHandle)?;

        if !entry.cap.perms.contains(Permissions::LINK) {
            return Err(TableError::PermissionDenied);
        }

        self.post.link(&entry.cap.address, &mailbox.address);
        Ok(())
    }

    pub async fn send(&self, handle: usize, data: &[u8], caps: &[usize]) -> Result<(), TableError> {
        // move into block to make this future Send
        let (address, mapped_caps) = {
            let inner = self.inner.lock();
            let entry = inner.entries.get(handle).ok_or(TableError::InvalidHandle)?;

            if !entry.cap.perms.contains(Permissions::SEND) {
                return Err(TableError::PermissionDenied);
            }

            let mut mapped_caps = Vec::with_capacity(caps.len());
            for cap in caps.iter() {
                let entry = inner.entries.get(*cap).ok_or(TableError::InvalidHandle)?;
                mapped_caps.push(entry.cap);
            }

            (entry.cap.address, mapped_caps)
        };

        self.post
            .send(
                &address,
                Signal::Message {
                    data,
                    caps: &mapped_caps,
                },
            )
            .await;

        Ok(())
    }

    pub fn kill(&self, handle: usize) -> Result<(), TableError> {
        let inner = self.inner.lock();
        let entry = inner.entries.get(handle).ok_or(TableError::InvalidHandle)?;

        if !entry.cap.perms.contains(Permissions::KILL) {
            return Err(TableError::PermissionDenied);
        }

        self.post.kill(&entry.cap.address);
        Ok(())
    }
}

/// A Rust-friendly handle to a capability within a [Table].
///
/// This struct's lifetime is tied to the [Table] that it lives within.
///
/// Cloning and dropping [CapabilityHandle] automatically increments and
/// decrements the reference count of the handle index, so there's no need to
/// manually manage capability ownership while using this struct.
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

    pub async fn send(
        &self,
        data: &[u8],
        caps: &[&CapabilityHandle<'_>],
    ) -> Result<(), TableError> {
        let mut mapped_caps = Vec::with_capacity(caps.len());
        for cap in caps.iter() {
            assert!(std::ptr::eq(cap.table, self.table));
            mapped_caps.push(cap.handle);
        }

        self.table.send(self.handle, data, &mapped_caps).await
    }

    pub fn kill(&self) -> Result<(), TableError> {
        self.table.kill(self.handle)
    }
}

/// A signal received through [Mailbox::recv] or [Mailbox::try_recv].
///
/// This enum is non-owning and facilitates zero-copy signal-sending. For
/// low-level scripting integrations or performance-sensitive signal handling,
/// this is fine. If you're not doing any of that, you probably want to use
/// [Mailbox::recv_owned] and [Mailbox::try_recv_owned] with
/// [OwnedContextSignal] instead.
///
/// Senders of non-owning signals wait for signals to be handled since they own
/// the signals' memory. Finish dealing with this signal in as quick and as
/// constant of a time as possible to avoid creating timing attack
/// vulnerabilities.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContextSignal<'a> {
    /// A notification that a capability linked to this mailbox has been killed.
    ///
    /// The handle owns a reference to a demoted version of the capability that
    /// was originally linked with no permission flags.
    Unlink { handle: usize },

    /// A message from another process.
    Message { data: &'a [u8], caps: Vec<usize> },
}

/// An owned signal received through [Mailbox::recv_owned] or [Mailbox::try_recv_owned].
///
/// A slower, owning version of [ContextSignal]. The generic lifetime parameter
/// of this object is tied to the lifetime of the current table and not to the
/// receiving of the message.
#[derive(Clone, Debug)]
pub enum OwnedContextSignal<'a> {
    /// A notification that a capability linked to this mailbox has been killed.
    ///
    /// The handle owns a reference to a demoted version of the capability that
    /// was originally linked with no permission flags.
    Unlink { handle: CapabilityHandle<'a> },

    /// A message from another process.
    Message {
        data: Vec<u8>,
        caps: Vec<CapabilityHandle<'a>>,
    },
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

/// A receiver for [ContextSignals][ContextSignal].
///
/// Processes create mailboxes in order to receive signals from other processes.
/// A process can close a mailbox, unlinking it from the other processes, or
/// a mailbox can be killed by other processes using [Permissions::KILL] on a
/// mailbox's capability. When a mailbox is killed, all of the other mailboxes
/// in its [MailboxStore] are killed as well.
///
/// To get started using mailboxes, see [Mailbox::recv]. If you don't need to
/// process zero-copy signals, you can call [Mailbox::recv_owned] instead.
/// [Mailbox::try_recv] and [Mailbox::try_recv_owned] poll the mailbox for new
/// signals without blocking.
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
    /// Receives a single signal from this mailbox.
    ///
    /// [ContextSignal] is non-owning, so this function takes a closure to map
    /// a temporary [ContextSignal] into types of a larger lifetime.
    ///
    /// Returns `None` when this mailbox's process has been killed.
    pub async fn recv<T>(&self, mut f: impl FnMut(ContextSignal) -> T) -> Option<T> {
        self.rx
            .recv(|signal| {
                let signal = self.store.table.map_signal(signal);
                f(signal)
            })
            .await
            .ok()
    }

    /// Receives a [OwnedContextSignal].
    ///
    /// Returns `None` when this mailbox's process has been killed.
    pub async fn recv_owned(&self) -> Option<OwnedContextSignal<'a>> {
        self.rx
            .recv(|signal| self.store.table.map_signal_owned(signal))
            .await
            .ok()
    }

    /// Polls this mailbox for any currently available signals.
    ///
    /// [ContextSignal] is non-owning, so this function takes a lambda to map
    /// a temporary [ContextSignal] into types of a larger lifetime.
    ///
    /// Returns:
    /// - `Some(Some(t))` when there was a signal available and it was mapped by the lambda.
    /// - `Some(None)` when there was not a signal available.
    /// - `None` when this mailbox's process has been killed.
    pub fn try_recv<T>(&self, mut f: impl FnMut(ContextSignal) -> T) -> Option<Option<T>> {
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

    /// Polls this mailbox for any currently available signals.
    ///
    /// Returns:
    /// - `Some(Some(t))` when there was a signal available.
    /// - `Some(None)` when there was not a signal available.
    /// - `None` when this mailbox's process has been killed.
    pub fn try_recv_owned(&self) -> Option<Option<OwnedContextSignal<'a>>> {
        let result = self
            .rx
            .try_recv(|signal| self.store.table.map_signal_owned(signal));

        match result {
            Ok(signal) => Some(Some(signal)),
            Err(flume::TryRecvError::Empty) => Some(None),
            Err(flume::TryRecvError::Disconnected) => None,
        }
    }

    /// Creates a capability within this mailbox's parent table to this mailbox's route.
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
        let table = Table::default();
        let mb_store = MailboxStore::new(&table);
        let mb = mb_store.create_mailbox().unwrap();
        let ad = mb.make_capability(Permissions::SEND);
        ad.send(b"Hello world!", &[]).await.unwrap();

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
        let table = Table::default();
        let mb_store = MailboxStore::new(&table);
        let mb = mb_store.create_mailbox().unwrap();
        let ad = mb.make_capability(Permissions::SEND);
        ad.send(b"", &[&ad]).await.unwrap();

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
    async fn table_send_impls_send() {
        let table = Table::default();

        tokio::spawn(async move {
            let mb_store = MailboxStore::new(&table);
            let mb = mb_store.create_mailbox().unwrap();
            let ad = mb.make_capability(Permissions::SEND);
            ad.send(b"Hello world!", &[]).await.unwrap();

            assert!(mb
                .recv(|s| {
                    s == ContextSignal::Message {
                        data: b"Hello world!",
                        caps: vec![],
                    }
                })
                .await
                .unwrap());
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn try_recv() {
        let table = Table::default();
        let mb_store = MailboxStore::new(&table);
        let mb = mb_store.create_mailbox().unwrap();

        assert_eq!(mb.try_recv(|_| ()), Some(None));

        let ad = mb.make_capability(Permissions::SEND);
        ad.send(b"Hello world!", &[]).await.unwrap();

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
        let table = Table::default();
        let mb_store = MailboxStore::new(&table);
        let mb = mb_store.create_mailbox().unwrap();
        let ad = mb.make_capability(Permissions::empty());
        let result = ad.send(b"", &[]).await;
        assert_eq!(result, Err(TableError::PermissionDenied));
    }

    #[tokio::test]
    async fn deny_kill() {
        let table = Table::default();
        let mb_store = MailboxStore::new(&table);
        let mb = mb_store.create_mailbox().unwrap();
        let ad = mb.make_capability(Permissions::empty());
        let result = ad.kill();
        assert_eq!(result, Err(TableError::PermissionDenied));
    }

    #[tokio::test]
    async fn deny_link() {
        let table = Table::default();
        let mb_store = MailboxStore::new(&table);
        let mb = mb_store.create_mailbox().unwrap();
        let ad = mb.make_capability(Permissions::empty());
        let result = ad.link(&mb);
        assert_eq!(result, Err(TableError::PermissionDenied));
    }

    #[tokio::test]
    async fn deny_demote_escalation() {
        let table = Table::default();
        let mb_store = MailboxStore::new(&table);
        let mb = mb_store.create_mailbox().unwrap();
        let ad = mb.make_capability(Permissions::KILL);
        let result = ad.demote(Permissions::SEND);
        assert_eq!(result.unwrap_err(), TableError::PermissionDenied);
    }

    #[tokio::test]
    async fn kill() {
        let table = Table::default();
        let mb_store = MailboxStore::new(&table);
        let mb = mb_store.create_mailbox().unwrap();
        let ad = mb.make_capability(Permissions::KILL);
        ad.kill().unwrap();
        assert_eq!(mb.recv(|s| format!("{:?}", s)).await, None);
    }

    #[tokio::test]
    async fn double_kill() {
        let table = Table::default();
        let mb_store = MailboxStore::new(&table);
        let mb = mb_store.create_mailbox().unwrap();
        let ad = mb.make_capability(Permissions::KILL);
        ad.kill().unwrap();
        ad.kill().unwrap();
        assert_eq!(mb.recv(|s| format!("{:?}", s)).await, None);
    }

    #[tokio::test]
    async fn dropped_handles_are_freed() {
        let table = Table::default();
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
        let table = Table::default();
        let mb_store = MailboxStore::new(&table);
        let mb1 = mb_store.create_mailbox().unwrap();
        let mb2 = mb_store.create_mailbox().unwrap();
        let ad = mb1.make_capability(Permissions::KILL);
        ad.kill().unwrap();
        assert_eq!(mb2.recv(|s| format!("{:?}", s)).await, None);
    }

    #[tokio::test]
    async fn unlink_on_kill() {
        let table = Table::default();
        let o_store = MailboxStore::new(&table);
        let object = o_store.create_mailbox().unwrap();

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
        let table = Table::default();
        let store = MailboxStore::new(&table);
        let s_mb = store.create_mailbox().unwrap();
        let s_cap = s_mb.make_capability(Permissions::LINK);
        let object = store.create_mailbox().unwrap();
        s_cap.link(&object).unwrap();
        drop(s_mb);

        let expected = ContextSignal::Unlink {
            handle: s_cap.demote(Permissions::empty()).unwrap().handle,
        };

        object.recv(move |s| assert_eq!(s, expected)).await.unwrap();
    }

    #[tokio::test]
    async fn unlink_dead() {
        let table = Table::default();
        let o_store = MailboxStore::new(&table);
        let object = o_store.create_mailbox().unwrap();

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
        let table = Table::default();
        let store = MailboxStore::new(&table);
        let s_mb = store.create_mailbox().unwrap();
        let s_cap = s_mb.make_capability(Permissions::LINK);
        let object = store.create_mailbox().unwrap();
        drop(s_mb);
        s_cap.link(&object).unwrap();

        let expected = ContextSignal::Unlink {
            handle: s_cap.demote(Permissions::empty()).unwrap().handle,
        };

        object.recv(move |s| assert_eq!(s, expected)).await.unwrap();
    }
}
