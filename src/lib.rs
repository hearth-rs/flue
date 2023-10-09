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

//! Flue is an efficient and secure actor runtime library.
//!
//! The fundamental building block in Flue is the **process**: a concurrent
//! execution thread with private memory. Processes may only communicate by
//! passing **signals** between each other. Signals are sent to **routes** and
//! received using **mailboxes**. All routes in a **route group** are killed if
//! any of them are killed. The **post office** contains all of the routes in a
//! set of communicating processes. **Capabilities** both reference and limit
//! access to routes using fine-grained permission flags. **Tables** are stores
//! of integer-addressed, unforgeable capabilities.
//!
//! Flue is made for the purpose of efficiently executing potentially untrusted
//! process code, so to support running that code, Flue's security model has
//! the following axioms:
//! - Routes can only be accessed by a process if a capability to that route
//!   has explicitly been passed to that process in a signal. You may sandbox
//!   a process on a fine-grained level by limiting which capabilities get
//!   passed to it.
//! - Capabilities may only be created from other capabilities with either an
//!   identical set or a subset of the original's permissions. Permission
//!   escalation by untrusted processes is impossible.
//!
//! Here's a box diagram of two processes who each have a mailbox and a
//! capability to the other's mailbox to help explain the mental model of a
//! full Flue-based actor system:
//!
//! ```
//!         Process A               Post Office               Process B
//! ┌───────────────────────┐     ┌─────────────┐     ┌───────────────────────┐
//! │         Table         │     │             │     │         Table         │
//! │ ┌───────────────────┐ │     │ ┌─────────┐ │     │ ┌───────────────────┐ │
//! │ │                   │ │     │ │         │ │     │ │                   │ │
//! │ │ ┌───────────────┐ │ │  ┌──┼─► Route B ├─┼───┐ │ │ ┌───────────────┐ │ │
//! │ │ │ Capability A  ├─┼─┼──┘  │ │         │ │   │ │ │ │ Capability B  ├─┼─┼─┐
//! │ │ └───────────────┘ │ │     │ └─────────┘ │   │ │ │ └───────────────┘ │ │ │
//! │ │                   │ │     │             │   │ │ │                   │ │ │
//! │ └────────▲──────────┘ │     │ ┌─────────┐ │   │ │ └────────▲──────────┘ │ │
//! │          │            │     │ │         │ │   │ │          │            │ │
//! │   ┌──────┴───────┐    │  ┌──┼─┤ Route A ◄─┼─┐ │ │   ┌──────┴───────┐    │ │
//! │   │   Mailbox A  ◄────┼──┘  │ │         │ │ │ └─┼───►   Mailbox B  │    │ │
//! │   └──────────────┘    │     │ └─────────┘ │ │   │   └──────────────┘    │ │
//! │                       │     │             │ │   │                       │ │
//! └───────────────────────┘     └─────────────┘ │   └───────────────────────┘ │
//!                                               │                             │
//!                                               └─────────────────────────────┘
//! ```
//!
//! Both processes share a post office, and mailboxes A and B have associated
//! routes A and B in that mailbox. Capability A belongs in process A's table
//! and references route B, and capability B lives in process B's table and
//! references route A. Mailboxes A and B reference their associated process's
//! table so that when they receive capabilities, they can insert those
//! capabilities into their process's table.
//!
//! To send a message signal from process A to process B using capability A,
//! Flue performs the following steps on that message:
//! 1. Process A's table confirms that capability A does indeed have the
//!    permission to send messages.
//! 2. Process A's table sends the message to route B's address in the post
//!    office.
//! 3. The post office looks up route B by address, finds mailbox B's zero-copy
//!    message channel, and uses it to send the message.
//! 4. The message waits in mailbox B's queue until mailbox B receives it.
//! 5. Mailbox B processes the message and inserts any capabilities inside of
//!    it into process B's table.

#![warn(missing_docs)]

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

/// A non-owning, internal signal using post office addresses.
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

/// An owning, internal signal using post office addresses.
///
/// Owning version of [Signal].
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

/// Shared state for a group of routes that are all killed when any of them
/// are killed.
struct RouteGroup {
    addresses: HashSet<Address>,
    dead: bool,
}

impl RouteGroup {
    /// Kills this route group exactly once.
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

/// A clearable connection to a [Mailbox]. Addressed in [PostOffice] by [Address].
struct Route {
    /// A sender to this route's associated [Mailbox].
    tx: Option<Sender<OwnedSignal>>,

    /// The [RouteGroup] that this route is a member of.
    group: Option<Arc<Mutex<RouteGroup>>>,

    /// A set of other routes that are linked to this route.
    ///
    /// This is taken when this route is closed.
    links: Mutex<Option<HashSet<Address>>>,

    /// The generation of this route. Routes that are allocated in the [PostOffice]
    /// with the same address are differentiated by generation.
    generation: u32,
}

impl Default for Route {
    fn default() -> Self {
        Self {
            tx: None,
            group: None,
            links: Mutex::new(Some(HashSet::new())),
            generation: 0,
        }
    }
}

impl Clear for Route {
    fn clear(&mut self) {
        self.tx.take();
        self.group.take();
        self.links.lock().take();
        self.generation += 1;
    }
}

/// Shared signal transport for all of the processes in a shared context.
///
/// Post offices store pools of routes and manage their lifetimes. This includes
/// sending messages, closing, killing, and linking them between each other.
///
/// Processes reference routes by their addresses, which along with
/// [Permissions] compose a capability.
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

    /// Inserts a new route into this post office and returns its new [Address].
    pub(crate) fn insert(&self, tx: Sender<OwnedSignal>, group: Arc<Mutex<RouteGroup>>) -> Address {
        let mut route = self.routes.create().unwrap();
        route.tx = Some(tx);
        route.group = Some(group);

        Address {
            handle: route.key(),
            generation: route.generation,
        }
    }

    /// Kills this route's route group.
    ///
    /// [RouteGroup::kill] calls [Self::close] on all of the route's group's
    /// members as a side effect of this function.
    pub(crate) fn kill(self: &Arc<Self>, address: &Address) {
        let Some(route) = self.get_route(address) else {
            return;
        };

        route.group.as_ref().unwrap().lock().kill(self);
    }

    /// Closes a route, frees its entry, and unlinks all routes linked to it.
    pub(crate) fn close(self: &Arc<Self>, address: &Address) {
        let Some(route) = self.get_route(address) else {
            return;
        };

        let Some(links) = route.links.lock().take() else {
            return;
        };

        let address = *address;
        let post = self.to_owned();

        // unlink asynchronously in order to return in constant time
        // mitigates timing attacks and eliminates delays in large networks of links
        tokio::spawn(async move {
            for link in links {
                post.send(&link, Signal::Unlink { address }).await;
            }
        });

        // mark this route for clearing
        self.routes.clear(address.handle);
    }

    /// Sends a signal to a route by address.
    ///
    /// This function is async because zero-copy signal sending needs to wait
    /// for the receiver to finish receiving before the signal's memory can be
    /// safely destroyed.
    pub(crate) async fn send(self: &Arc<Self>, address: &Address, signal: Signal<'_>) {
        // nest in block to make this function's future impl Send
        let result = {
            let Some(route) = self.get_route(address) else {
                return;
            };

            // fetch sender, if available
            let Some(tx) = &route.tx else {
                return;
            };

            // send signal
            tx.send(signal)
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

    /// Links the object route to the subject route.
    ///
    /// When the subject route is closed, the object route will receive
    /// [Signal::Unlink] with the subject's address.
    pub(crate) fn link(self: &Arc<Self>, subject: &Address, object: &Address) {
        // shorthand to immediately unlink if the route is closed at the
        // time of linking
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
            // if the address is invalid, the route must be closed
            unlink();
            return;
        };

        let mut links_lock = route.links.lock();
        let Some(links) = links_lock.as_mut() else {
            // if links is taken, the route must be closed
            unlink();
            return;
        };

        let Some(tx) = &route.tx else {
            // if the sender has been removed, the route must be closed
            unlink();
            return;
        };

        if tx.receiver_count() == 0 {
            // if the receiver has hung up, the route must be closed
            unlink();
            return;
        }

        // insert the link object
        links.insert(*object);
    }

    /// Internal helper function to look up a route by address (including generation).
    fn get_route(&self, address: &Address) -> Option<impl Deref<Target = Route> + '_> {
        let route = self.routes.get(address.handle)?;

        if route.generation != address.generation {
            None
        } else {
            Some(route)
        }
    }
}

/// An address of a signal route in a [PostOffice].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Address {
    /// The index of this route in the post office's route pool.
    pub(crate) handle: usize,

    /// The generation of this address's handle.
    pub(crate) generation: u32,
}

/// A capability to a route in a [PostOffice].
///
/// This includes both the [Address] of the route and the [Permissions] of the
/// operations that can be performed on that route with this capability.
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

/// Mutable state in a [Table]. Stores the table's capabilities, their
/// reference counts, and a capability-keyed reverse lookup table of existing
/// entries.
struct TableInner {
    entries: Slab<TableEntry>,
    reverse_entries: HashMap<Capability, usize>,
}

impl TableInner {
    /// Inserts a [Capability] into this table. Reuses existing capability
    /// handles and increments their reference count if available.
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

    /// Imports a table-less [Signal] to a table-local [ContextSignal].
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

    /// Imports a table-less [Signal] to a table-local [OwnedContextSignal].
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
            Arc::as_ptr(&mailbox.group.table.post)
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

    /// Retrieves the [Permissions] of a capability handle.
    pub fn get_permissions(&self, handle: usize) -> Result<Permissions, TableError> {
        self.inner
            .lock()
            .entries
            .get(handle)
            .ok_or(TableError::InvalidHandle)
            .map(|e| e.cap.perms)
    }

    /// Creates a new capability from an existing one with a subset of the original's [Permissions].
    ///
    /// Returns [TableError::PermissionDenied] if the permissions requested are
    /// not in the original's.
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

    /// Links a capability handle to a given mailbox.
    ///
    /// When the capability's route is closed, the mailbox will receive an
    /// unlink signal ([ContextSignal::Unlink] or [OwnedContextSignal::Unlink])
    /// with a capability handle of a demoted version of the linked capability
    /// *but with no [Permissions]*.
    ///
    /// Returns [TableError::PermissionDenied] if the capability does not have
    /// [Permissions::LINK].
    ///
    /// Panics if the mailbox's table is not this table.
    pub fn link(&self, handle: usize, mailbox: &Mailbox) -> Result<(), TableError> {
        assert!(std::ptr::eq(mailbox.group.table, self));
        let inner = self.inner.lock();
        let entry = inner.entries.get(handle).ok_or(TableError::InvalidHandle)?;

        if !entry.cap.perms.contains(Permissions::LINK) {
            return Err(TableError::PermissionDenied);
        }

        self.post.link(&entry.cap.address, &mailbox.address);
        Ok(())
    }

    /// Sends a message to the given capability handle.
    ///
    /// This function is async because zero-copy sending of signals needs to
    /// wait for the receiver to finish consuming the sent data before returning
    /// in order to safely capture the lifetime of the data.
    ///
    /// Returns [TableError::PermissionDenied] if the destination capability
    /// does not have [Permissions::SEND].
    ///
    /// Returns [TableError::InvalidHandle] if `handle` or any of `caps` are
    /// invalid within this table.
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

    /// Kills a capability handle.
    ///
    /// This does NOT decrement the reference count of the handle; only
    /// attempts to kill it.
    ///
    /// Returns [TableError::PermissionDenied] if the given capability does not
    /// have [Permissions::KILL].
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

    /// Creates a freestanding [OwnedCapability] from this capability handle.
    pub fn to_owned(&self) -> OwnedCapability {
        self.table.get_owned(self.handle).unwrap()
    }

    /// Retrieves the [Permissions] of this capability handle.
    pub fn get_permissions(&self) -> Permissions {
        self.table.get_permissions(self.handle).unwrap()
    }

    /// Creates a new [CapabilityHandle] with a subset of the [Permissions] of this one.
    ///
    /// Returns [TableError::PermissionDenied] if the permissions requested are
    /// not in this one's.
    pub fn demote(&self, perms: Permissions) -> Result<Self, TableError> {
        Ok(Self {
            table: self.table,
            handle: self.table.demote(self.handle, perms)?,
        })
    }

    /// Links this capability handle to a given mailbox.
    ///
    /// When this capability's route is closed, the mailbox will receive an
    /// unlink signal ([ContextSignal::Unlink] or [OwnedContextSignal::Unlink])
    /// with a capability handle of a demoted version of this capability *but
    /// with no [Permissions]*.
    ///
    /// Returns [TableError::PermissionDenied] if this capability does not have
    /// [Permissions::LINK].
    ///
    /// Panics if the mailbox's table is not this table.
    pub fn link(&self, mailbox: &Mailbox<'a>) -> Result<(), TableError> {
        self.table.link(self.handle, mailbox)
    }

    /// Sends a message to this capability handle.
    ///
    /// This function is async because zero-copy sending of signals needs to
    /// wait for the receiver to finish consuming the sent data before returning
    /// in order to safely capture the lifetime of the data.
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

    /// Kills this capability handle.
    ///
    /// Returns [TableError::PermissionDenied] if this capability does not have
    /// [Permissions::KILL].
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
    Unlink {
        /// An owning handle of a demoted version of the capability that was
        /// originally linked but with no [Permissions].
        handle: usize,
    },

    /// A message from another process.
    Message {
        /// This message's data as a raw byte array.
        data: &'a [u8],

        /// The capabilities sent in this message.
        caps: Vec<usize>,
    },
}

/// An owned signal received through [Mailbox::recv_owned] or [Mailbox::try_recv_owned].
///
/// A slower, owning version of [ContextSignal]. The generic lifetime parameter
/// of this object is tied to the lifetime of the current table and not to the
/// receiving of the message.
#[derive(Clone, Debug)]
pub enum OwnedContextSignal<'a> {
    /// A notification that a capability linked to this mailbox has been killed.
    Unlink {
        /// An owning handle of a demoted version of the capability that was
        /// originally linked but with no [Permissions].
        handle: CapabilityHandle<'a>,
    },

    /// A message from another process.
    Message {
        /// This message's data as a raw byte array.
        data: Vec<u8>,

        /// The capabilities sent in this message.
        caps: Vec<CapabilityHandle<'a>>,
    },
}

/// A factory for [Mailbox]s that belong to the same route group.
///
/// Create a mailbox group for a table using [MailboxGroup::new], then create
/// mailboxes using [MailboxGroup::create_mailbox]. When the mailboxes from
/// this group are killed, you cannot create any more mailboxes. You can check
/// if this mailbox group is still alive without polling mailboxes using
/// [MailboxGroup::poll_dead].
///
/// There is a one-to-many relationship between [Table] and [MailboxGroup], so
/// create as many groups as you want. However, in most cases where you're only
/// executing a single process per [Table], you're only going to need a single
/// group.
pub struct MailboxGroup<'a> {
    table: &'a Table,
    group: Arc<Mutex<RouteGroup>>,
}

impl<'a> MailboxGroup<'a> {
    /// Creates a new mailbox group for the given [Table].
    pub fn new(table: &'a Table) -> Self {
        Self {
            table,
            group: Arc::new(Mutex::new(RouteGroup {
                addresses: HashSet::new(),
                dead: false,
            })),
        }
    }

    /// Creates a new mailbox. Returns `None` if this mailbox group has been killed.
    pub fn create_mailbox(&self) -> Option<Mailbox<'_>> {
        let mut group = self.group.lock();

        if group.dead {
            return None;
        }

        let (tx, rx) = channel();
        let address = self.table.post.insert(tx, self.group.clone());
        group.addresses.insert(address);

        Some(Mailbox {
            group: self,
            address,
            rx,
        })
    }

    /// Checks if this mailbox group has been killed.
    pub fn poll_dead(&self) -> bool {
        self.group.lock().dead
    }
}

/// A receiver for [ContextSignals][ContextSignal].
///
/// Processes create mailboxes in order to receive signals from other processes.
/// A process can close a mailbox, unlinking it from the other processes, or
/// a mailbox can be killed by other processes using [Permissions::KILL] on a
/// mailbox's capability. When a mailbox is killed, all of the other mailboxes
/// in its [MailboxGroup] are killed as well.
///
/// To get started using mailboxes, see [Mailbox::recv]. If you don't need to
/// process zero-copy signals, you can call [Mailbox::recv_owned] instead.
/// [Mailbox::try_recv] and [Mailbox::try_recv_owned] poll the mailbox for new
/// signals without blocking.
pub struct Mailbox<'a> {
    group: &'a MailboxGroup<'a>,
    address: Address,
    rx: Receiver<OwnedSignal>,
}

impl<'a> Drop for Mailbox<'a> {
    fn drop(&mut self) {
        self.group.table.post.close(&self.address);
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
                let signal = self.group.table.map_signal(signal);
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
            .recv(|signal| self.group.table.map_signal_owned(signal))
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
            let signal = self.group.table.map_signal(signal);
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
            .try_recv(|signal| self.group.table.map_signal_owned(signal));

        match result {
            Ok(signal) => Some(Some(signal)),
            Err(flume::TryRecvError::Empty) => Some(None),
            Err(flume::TryRecvError::Disconnected) => None,
        }
    }

    /// Creates a capability within this mailbox's parent table to this mailbox's route.
    pub fn make_capability(&self, perms: Permissions) -> CapabilityHandle<'a> {
        let handle = self.group.table.insert(Capability {
            address: self.address,
            perms,
        });

        CapabilityHandle {
            table: self.group.table,
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
        let group = MailboxGroup::new(&table);
        let mb = group.create_mailbox().unwrap();
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
        let group = MailboxGroup::new(&table);
        let mb = group.create_mailbox().unwrap();
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
            let group = MailboxGroup::new(&table);
            let mb = group.create_mailbox().unwrap();
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
        let group = MailboxGroup::new(&table);
        let mb = group.create_mailbox().unwrap();

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
        let group = MailboxGroup::new(&table);
        let mb = group.create_mailbox().unwrap();
        let ad = mb.make_capability(Permissions::empty());
        let result = ad.send(b"", &[]).await;
        assert_eq!(result, Err(TableError::PermissionDenied));
    }

    #[tokio::test]
    async fn deny_kill() {
        let table = Table::default();
        let group = MailboxGroup::new(&table);
        let mb = group.create_mailbox().unwrap();
        let ad = mb.make_capability(Permissions::empty());
        let result = ad.kill();
        assert_eq!(result, Err(TableError::PermissionDenied));
    }

    #[tokio::test]
    async fn deny_link() {
        let table = Table::default();
        let group = MailboxGroup::new(&table);
        let mb = group.create_mailbox().unwrap();
        let ad = mb.make_capability(Permissions::empty());
        let result = ad.link(&mb);
        assert_eq!(result, Err(TableError::PermissionDenied));
    }

    #[tokio::test]
    async fn deny_demote_escalation() {
        let table = Table::default();
        let group = MailboxGroup::new(&table);
        let mb = group.create_mailbox().unwrap();
        let ad = mb.make_capability(Permissions::KILL);
        let result = ad.demote(Permissions::SEND);
        assert_eq!(result.unwrap_err(), TableError::PermissionDenied);
    }

    #[tokio::test]
    async fn kill() {
        let table = Table::default();
        let group = MailboxGroup::new(&table);
        let mb = group.create_mailbox().unwrap();
        let ad = mb.make_capability(Permissions::KILL);
        ad.kill().unwrap();
        assert_eq!(mb.recv(|s| format!("{:?}", s)).await, None);
    }

    #[tokio::test]
    async fn double_kill() {
        let table = Table::default();
        let group = MailboxGroup::new(&table);
        let mb = group.create_mailbox().unwrap();
        let ad = mb.make_capability(Permissions::KILL);
        ad.kill().unwrap();
        ad.kill().unwrap();
        assert_eq!(mb.recv(|s| format!("{:?}", s)).await, None);
    }

    #[tokio::test]
    async fn dropped_handles_are_freed() {
        let table = Table::default();
        let group = MailboxGroup::new(&table);
        let mb = group.create_mailbox().unwrap();
        let ad = mb.make_capability(Permissions::empty());
        let handle = ad.handle;
        assert!(table.is_valid(handle));
        drop(ad);
        assert!(!table.is_valid(handle));
    }

    #[tokio::test]
    async fn kill_all_mailboxes() {
        let table = Table::default();
        let group = MailboxGroup::new(&table);
        let mb1 = group.create_mailbox().unwrap();
        let mb2 = group.create_mailbox().unwrap();
        let ad = mb1.make_capability(Permissions::KILL);
        ad.kill().unwrap();
        assert_eq!(mb2.recv(|s| format!("{:?}", s)).await, None);
    }

    #[tokio::test]
    async fn unlink_on_kill() {
        let table = Table::default();
        let o_group = MailboxGroup::new(&table);
        let object = o_group.create_mailbox().unwrap();

        let child = table.spawn();
        let s_group = MailboxGroup::new(&child);
        let s_mb = s_group.create_mailbox().unwrap();

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
        let group = MailboxGroup::new(&table);
        let s_mb = group.create_mailbox().unwrap();
        let s_cap = s_mb.make_capability(Permissions::LINK);
        let object = group.create_mailbox().unwrap();
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
        let o_group = MailboxGroup::new(&table);
        let object = o_group.create_mailbox().unwrap();

        let child = table.spawn();
        let s_group = MailboxGroup::new(&child);
        let s_mb = s_group.create_mailbox().unwrap();

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
        let group = MailboxGroup::new(&table);
        let s_mb = group.create_mailbox().unwrap();
        let s_cap = s_mb.make_capability(Permissions::LINK);
        let object = group.create_mailbox().unwrap();
        drop(s_mb);
        s_cap.link(&object).unwrap();

        let expected = ContextSignal::Unlink {
            handle: s_cap.demote(Permissions::empty()).unwrap().handle,
        };

        object.recv(move |s| assert_eq!(s, expected)).await.unwrap();
    }
}
