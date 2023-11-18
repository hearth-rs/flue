// Copyright (c) 2023 Marceline Cramer
// Copyright (c) 2023 Roux
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
//! Flue's purpose is to be a support library for concurrency-oriented
//! programs using **processes**: concurrent execution threads with private
//! memory. Processes may only communicate by passing **signals** between each
//! other. Signals are sent to **routes** and received using **mailboxes**. All
//! routes in a **route group** are killed if any of them are killed. The **post
//! office** contains all of the routes in a set of communicating processes.
//! **Capabilities** both reference and limit access to routes using fine-
//! grained permission flags. **Tables** are stores of integer- addressed,
//! unforgeable capabilities.
//!
//! Although Flue provides the low-level support framework and data model
//! for building process-based concurrent programs, it does *NOT* provide a
//! high-level definition or data type for processes themselves. Users of the
//! Flue library must combine Flue's components with their application's
//! specific data model in order to find the best architecture for their
//! concurrent system.
//!
//! Please note that signals may **only** be sent to routes and that mailboxes
//! may **only** receive signals through the routes that they are bound to.
//!
//! Capabilities may be used to perform the following operations on their
//! routes, each of which are guarded by their respective permission flag:
//! 1. **Kill**: Forcibly terminate the route and all of the other routes in its
//!    route group, preventing them from receiving any further messages.
//! 2. **Send**: Send a "message" signal to the destination route
//!    comprised of data (a simple byte buffer) and a list of capabilities to be
//!    imported into the route's mailbox's table.
//! 3. **Monitor**: Configures a given mailbox to monitor the capability's
//!    route. When the route is closed, either by choice or because of it being
//!    killed, the mailbox receives a "down" signal with a permission-less
//!    capability to the monitored route. If the route is already closed at the
//!    time of monitoring, the mailbox will immediately receive the down signal.
//! 4. **Link**: Links a given route group to the capability's route group.
//!    When either route group dies, the other will also be killed. If either
//!    group is already dead, the other will be immediately killed. A link can
//!    be removed at any time by **unlinking** the two route groups. Unlike
//!    monitoring, a link between two route groups persists even if the linked
//!    capability's route is closed.
//!
//! A capability may also be "demoted" to a new capability that refers to the
//! same route but with a subset of the original's permissions. This can be
//! used to limit another's process access to a route by restricting the
//! permission flags on the route's capability that is sent to that process.
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
//! ```text
//!         Process A              Post Office               Process B
//! ┌───────────────────────┐    ┌─────────────┐     ┌───────────────────────┐
//! │         Table         │    │             │     │         Table         │
//! │ ┌───────────────────┐ │    │ ┌─────────┐ │     │ ┌───────────────────┐ │
//! │ │                   │ │    │ │         │ │     │ │                   │ │
//! │ │ ┌───────────────┐ │ │ ┌──┼─► Route B ├─┼───┐ │ │ ┌───────────────┐ │ │
//! │ │ │ Capability A  ├─┼─┼─┘  │ │         │ │   │ │ │ │ Capability B  ├─┼─┼─┐
//! │ │ └───────────────┘ │ │    │ └─────────┘ │   │ │ │ └───────────────┘ │ │ │
//! │ │                   │ │    │             │   │ │ │                   │ │ │
//! │ └────────▲──────────┘ │    │ ┌─────────┐ │   │ │ └────────▲──────────┘ │ │
//! │          │            │    │ │         │ │   │ │          │            │ │
//! │   ┌──────┴───────┐    │ ┌──┼─┤ Route A ◄─┼─┐ │ │   ┌──────┴───────┐    │ │
//! │   │   Mailbox A  ◄────┼─┘  │ │         │ │ │ └─┼───►   Mailbox B  │    │ │
//! │   └──────────────┘    │    │ └─────────┘ │ │   │   └──────────────┘    │ │
//! │                       │    │             │ │   │                       │ │
//! └───────────────────────┘    └─────────────┘ │   └───────────────────────┘ │
//!                                              │                             │
//!                                              └─────────────────────────────┘
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

#[cfg(test)]
mod tests;

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

        /// The permission to monitor this capability and be notified of its
        /// closure.
        const MONITOR = 1 << 1;

        /// The permission to kill this capability.
        const KILL = 1 << 2;

        /// The permission to link to this capability, comprised of both the
        /// [Self::MONITOR] and [Self::KILL] permissions.
        const LINK = (1 << 1) | (1 << 0);
    }
}

/// A non-owning signal using route addresses scoped within the post office.
#[derive(Clone, Copy, Debug)]
enum RouteSignal<'a> {
    Down {
        address: RouteAddress,
    },
    Message {
        data: &'a [u8],
        caps: &'a [Capability],
    },
}

impl<'a> NonOwningMessage<'a> for RouteSignal<'a> {
    type Owning = OwnedRouteSignal;

    fn to_owned(self) -> OwnedRouteSignal {
        match self {
            RouteSignal::Down { address } => OwnedRouteSignal::Down { address },
            RouteSignal::Message { data, caps } => OwnedRouteSignal::Message {
                data: data.to_vec(),
                caps: caps.to_vec(),
            },
        }
    }
}

/// An owning signal using route addresses scoped within the post office.
///
/// Owning version of [RouteSignal].
enum OwnedRouteSignal {
    Down {
        address: RouteAddress,
    },
    Message {
        data: Vec<u8>,
        caps: Vec<Capability>,
    },
}

impl OwningMessage for OwnedRouteSignal {
    type NonOwning<'a> = RouteSignal<'a>;

    fn to_non_owned(&self) -> Self::NonOwning<'_> {
        match self {
            OwnedRouteSignal::Down { address } => RouteSignal::Down { address: *address },
            OwnedRouteSignal::Message { data, caps } => RouteSignal::Message {
                data: data.as_slice(),
                caps: caps.as_slice(),
            },
        }
    }
}

/// Protected, mutable route group state that can only be accessed by the
/// methods on [RouteGroup].
#[derive(Default)]
struct RouteGroupInner {
    addresses: HashSet<RouteAddress>,
    dead: bool,
    links: Vec<Arc<RouteGroup>>,
}

impl RouteGroupInner {
    /// Kills this route group exactly once.
    fn kill(&mut self, post: &Arc<PostOffice>) {
        if self.dead {
            return;
        }

        self.dead = true;

        // close all of this group's routes
        for address in self.addresses.iter() {
            post.close(address);
        }

        // kill links asynchronously in order to return in constant time
        // mitigates timing attacks and eliminates delays
        // also avoids deadlocks when a linked process tries to lock this process to kill it
        tokio::spawn({
            // move owned values into the task
            // take links to avoid cyclic route group references
            let links = std::mem::take(&mut self.links);
            let post = post.clone();

            async move {
                for link in links {
                    link.kill(&post);
                }
            }
        });
    }
}

/// Shared state for a group of routes that are all killed when any of them
/// are killed.
#[derive(Default)]
pub struct RouteGroup {
    /// A protected mutex containing this route group's mutable data.
    inner: Mutex<RouteGroupInner>,
}

impl RouteGroup {
    /// Kills this route group exactly once.
    pub fn kill(&self, post: &Arc<PostOffice>) {
        self.inner.lock().kill(post);
    }

    /// Gets if this route group is dead.
    pub fn is_dead(&self) -> bool {
        self.inner.lock().dead
    }

    /// Links two route groups together.
    ///
    /// Kills the other if either one is already dead.
    ///
    /// Does nothing if the same route group is linked against itself.
    pub fn link(post: &Arc<PostOffice>, a: &Arc<Self>, b: &Arc<Self>) {
        // check that the groups are not the same
        if Arc::ptr_eq(a, b) {
            return;
        }

        // lock both groups simultaneously
        let mut a_inner = a.inner.lock();
        let mut b_inner = b.inner.lock();

        // kill the other if either is dead while keeping the locks
        if a_inner.dead != b_inner.dead {
            if a_inner.dead {
                b_inner.kill(post);
            } else {
                a_inner.kill(post);
            }

            return;
        }

        // add each other to their link lists
        a_inner.links.push(b.clone());
        b_inner.links.push(a.clone());
    }

    /// Unlinks two linked route groups.
    ///
    /// Does nothing if the two groups are not linked.
    pub fn unlink(a: &Arc<Self>, b: &Arc<Self>) {
        // lock both groups simultaneously
        let mut a_inner = a.inner.lock();
        let mut b_inner = b.inner.lock();

        // early exit if either is dead
        if a_inner.dead || b_inner.dead {
            return;
        }

        // remove each other's references
        a_inner.links.retain(|link| !Arc::ptr_eq(link, b));
        b_inner.links.retain(|link| !Arc::ptr_eq(link, a));
    }
}

/// A clearable connection to a [Mailbox]. Addressed in [PostOffice] by [RouteAddress].
struct Route {
    /// A sender to this route's associated [Mailbox].
    tx: Option<Sender<OwnedRouteSignal>>,

    /// The [RouteGroup] that this route is a member of.
    group: Option<Arc<RouteGroup>>,

    /// A set of other routes that are monitoring this route.
    ///
    /// This is taken when this route is closed.
    monitors: Mutex<Option<HashSet<RouteAddress>>>,

    /// The generation of this route.
    ///
    /// Because [Pool] can allocate a new route with a reused [RouteHandle]
    /// to an old route that has been closed, using [RouteHandle] alone to
    /// access routes could potentially lead to outstanding handles to the old
    /// route instead sending signals to new routes. Instead of a complicated,
    /// inefficient garbage collection or reference counting system that can
    /// ensure that routes are never freed until all of their references are
    /// gone, we simply store a persistent generation counter that is
    /// incremented whenever the route at its handle is closed. Then, the
    /// generation is used together with [RouteHandle] in [RouteAddress] to
    /// access routes.
    ///
    /// Note that the [sharded_slab] crate we're using also has a
    /// [sharded_slab::Slab] type that includes the generation in its handle,
    /// however, that generation has only a handful of bits available because
    /// other data needs to be included in the bits of a `usize`. Very old
    /// route handles could potentially refer to new routes if that generation
    /// overflows. Instead, we manually use the [Pool] type so that we can use
    /// a full `u32` to represent the generation that will never overflow in
    /// practice.
    generation: u32,
}

impl Default for Route {
    fn default() -> Self {
        Self {
            tx: None,
            group: None,
            monitors: Mutex::new(None),
            generation: 0,
        }
    }
}

impl Clear for Route {
    fn clear(&mut self) {
        self.tx.take();
        self.group.take();
        self.monitors.lock().take();
        self.generation += 1;
    }
}

/// A handle to a route.
///
/// Routes are stored in the [PostOffice]'s pool and are indexed by a `usize`.
/// This struct is used to store the handle of a route in its corresponding [RouteAddress].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct RouteHandle(usize);

/// Shared signal transport for all of the processes in a shared context.
///
/// Post offices store pools of routes and manage their lifetimes. This includes
/// sending signals, closing, killing, and monitoring each other.
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

    /// Inserts a new route in the given route group into this post office and
    /// returns its new [RouteAddress].
    ///
    /// Returns `None` if the route group is dead.
    pub(crate) fn insert(
        &self,
        tx: Sender<OwnedRouteSignal>,
        group: Arc<RouteGroup>,
    ) -> Option<RouteAddress> {
        // lock the route group so we can mutate it
        let mut group_inner = group.inner.lock();

        // immediately abort if the group is dead
        if group_inner.dead {
            return None;
        }

        // create a new route
        let mut route = self.routes.create().unwrap();

        // get the new route's address
        let address = RouteAddress {
            handle: RouteHandle(route.key()),
            generation: route.generation,
        };

        // add the address to the route group
        group_inner.addresses.insert(address);

        // unlock the mutex so we can move the group into the route entry
        drop(group_inner);

        // initialize the route entry
        route.tx = Some(tx);
        route.group = Some(group);
        *route.monitors.lock() = Some(HashSet::new());

        // return the new address
        Some(address)
    }

    /// Kills this route's route group.
    ///
    /// [RouteGroup::kill] calls [Self::close] on all of the route's group's
    /// members as a side effect of this function.
    pub(crate) fn kill(self: &Arc<Self>, address: &RouteAddress) {
        let Some(route) = self.get_route(address) else {
            return;
        };

        route.group.as_ref().unwrap().kill(self);
    }

    /// Closes a route, frees its entry, and sends down signals to all routes
    /// monitoring it.
    pub(crate) fn close(self: &Arc<Self>, address: &RouteAddress) {
        let Some(route) = self.get_route(address) else {
            return;
        };

        let Some(monitors) = route.monitors.lock().take() else {
            return;
        };

        // send down signals asynchronously in order to return in constant time
        // mitigates timing attacks and eliminates delays
        tokio::spawn({
            // move owned values into the task
            let address = *address;
            let post = self.to_owned();

            async move {
                for monitor in monitors {
                    post.send(&monitor, RouteSignal::Down { address }).await;
                }
            }
        });

        // mark this route for clearing
        self.routes.clear(address.handle.0);
    }

    /// Sends a signal to a route by address.
    ///
    /// This function is async because zero-copy signal sending needs to wait
    /// for the receiver to finish receiving before the signal's memory can be
    /// safely destroyed.
    pub(crate) async fn send(self: &Arc<Self>, address: &RouteAddress, signal: RouteSignal<'_>) {
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

    /// Monitors the subject route from the object route.
    ///
    /// When the subject route is closed, the object route will receive
    /// [Signal::Down] with the subject's address.
    pub(crate) fn monitor(self: &Arc<Self>, subject: &RouteAddress, object: &RouteAddress) {
        // shorthand to immediately send a down signal if the route is closed
        // at the time of monitoring
        let down = || {
            let subject = *subject;
            let object = *object;
            let post = self.to_owned();
            tokio::spawn(async move {
                post.send(&object, RouteSignal::Down { address: subject })
                    .await;
                post.close(&subject);
            })
        };

        let Some(route) = self.get_route(subject) else {
            // if the address is invalid, the route must be closed
            down();
            return;
        };

        let mut monitors_lock = route.monitors.lock();
        let Some(monitors) = monitors_lock.as_mut() else {
            // if monitors is taken, the route must be closed
            down();
            return;
        };

        let Some(tx) = &route.tx else {
            // if the sender has been removed, the route must be closed
            down();
            return;
        };

        if tx.receiver_count() == 0 {
            // if the receiver has hung up, the route must be closed
            down();
            return;
        }

        monitors.insert(*object);
    }

    /// Links the route group of a given route to a route group.
    pub(crate) fn link(self: &Arc<Self>, route: &RouteAddress, group: &Arc<RouteGroup>) {
        let Some(route) = self.get_route(route) else {
            return;
        };

        RouteGroup::link(self, route.group.as_ref().unwrap(), group);
    }

    /// Unlinks the route group of a given route from a route group.
    pub(crate) fn unlink(self: &Arc<Self>, route: &RouteAddress, group: &Arc<RouteGroup>) {
        let Some(route) = self.get_route(route) else {
            return;
        };

        RouteGroup::unlink(route.group.as_ref().unwrap(), group);
    }

    /// Internal helper function to look up a route by address (including generation).
    fn get_route(&self, address: &RouteAddress) -> Option<impl Deref<Target = Route> + '_> {
        let route = self.routes.get(address.handle.0)?;

        if route.generation != address.generation {
            None
        } else {
            Some(route)
        }
    }
}

/// An address of a signal route in a [PostOffice].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct RouteAddress {
    /// The index of this route in the post office's route pool.
    pub handle: RouteHandle,

    /// The generation of this address's handle.
    pub generation: u32,
}

/// A capability to a route in a [PostOffice].
///
/// This includes both the [RouteAddress] of the route and the [Permissions] of
/// the operations that can be performed on that route with this capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Capability {
    pub address: RouteAddress,
    pub perms: Permissions,
}

/// A freestanding capability that is not tied to any [Table].
///
/// This can be used to conveniently transfer single capabilities from one
/// table to another without needing to send and receive messages.
///
/// You can get and insert owned capabilities using [Table::get_owned] and
/// [Table::import_owned]. Please keep in mind that owned capabilities have
/// an `Arc<PostOffice>` inside and are thus relatively expensive to clone and
/// destroy. Minimize their usage in performance-critical code.
#[derive(Clone)]
pub struct OwnedCapability {
    inner: Capability,
    post: Arc<PostOffice>,
}

impl PartialEq for OwnedCapability {
    fn eq(&self, other: &Self) -> bool {
        (self.inner == other.inner) && Arc::ptr_eq(&self.post, &other.post)
    }
}

impl Eq for OwnedCapability {}

impl Debug for OwnedCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnedCapability")
            .field("inner", &self.inner)
            .finish()
    }
}

/// An error in performing a capability operation in a [Table].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TableError {
    /// A handle used in this table operation was invalid.
    InvalidHandle,

    /// A handle used in this table operation does not have sufficient permissions.
    PermissionDenied,

    /// A handle used in this table operation belongs to a different post office
    /// than the one referenced by this table.
    PostOfficeMismatch,

    /// Something in this operation belongs to a different table than expected
    TableMismatch,
}

type TableResult<T> = Result<T, TableError>;

impl Display for TableError {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            TableError::InvalidHandle => write!(fmt, "invalid handle"),
            TableError::PermissionDenied => write!(fmt, "permission denied"),
            TableError::PostOfficeMismatch => write!(fmt, "post office mismatch"),
            TableError::TableMismatch => write!(fmt, "table mismatch"),
        }
    }
}

impl std::error::Error for TableError {}

#[derive(Debug)]
struct TableEntry {
    cap: Capability,
    ref_count: usize,
}

/// Mutable state in a [Table]. Stores the table's capabilities, their
/// reference counts, and a capability-keyed reverse lookup table of existing
/// entries.
struct TableInner {
    entries: Slab<TableEntry>,
    reverse_entries: HashMap<Capability, CapabilityHandle>,
}

impl TableInner {
    /// Inserts a [Capability] into this table. Reuses existing capability
    /// handles and increments their reference count if available.
    pub fn import(&mut self, cap: Capability) -> CapabilityHandle {
        use std::collections::hash_map::Entry;
        let entry = self.reverse_entries.entry(cap);
        match entry {
            Entry::Occupied(handle) => {
                let handle = *handle.get();
                self.entries.get_mut(handle.0).unwrap().ref_count += 1;
                handle
            }
            Entry::Vacant(reverse_entry) => {
                let ref_count = 1;
                let entry = TableEntry { cap, ref_count };
                let handle = self.entries.insert(entry);
                reverse_entry.insert(CapabilityHandle(handle));
                CapabilityHandle(handle)
            }
        }
    }
}

/// An integer handle to a capability within a [Table].
///
/// This is a low-level type for directing managing capability handles. You
/// should manually call [Table::inc_ref] and [Table::dec_ref] for the lifetime
/// of this type. If you're looking for a friendlier capability API, check out
/// [CapabilityRef].
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct CapabilityHandle(pub usize);

/// Contains unforgeable capabilities, performs operations on them, and moderates
/// access to them.
///
/// Each capability in a [Table] is referenced by an opaque integer handle,
/// stored in the [CapabilityHandle] type. Handles are reference-counted, and
/// are freed when their refcount hits zero.
///
/// This struct has low-level operations on capability handles, but unless
/// you're doing low-level integration of a table into a scripting environment,
/// you probably want to use [CapabilityRef] instead, which provides some
/// higher-level abstraction for handle ownership.
///
/// All incoming capabilities to this table are mapped to handles, and identical
/// capabilities are given owning references to the same handle. If two handles
/// have the same integer value, then they are identical. Please note that
/// the equivalence of capabilities is determined by both that capability's
/// address (the route it actually points to) **AND** its [Permissions]. Two
/// capabilities can point to the same route but be nonequivalent because they
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
    pub fn get_owned(&self, handle: CapabilityHandle) -> TableResult<OwnedCapability> {
        let inner = self
            .inner
            .lock()
            .entries
            .get(handle.0)
            .ok_or(TableError::InvalidHandle)?
            .cap;

        let post = self.post.clone();

        Ok(OwnedCapability { inner, post })
    }

    /// Directly inserts an [OwnedCapability] into this table.
    ///
    /// Returns [TableError::PostOfficeMismatch] if the capability has a different [PostOffice].
    pub fn import_owned(&self, cap: OwnedCapability) -> TableResult<CapabilityHandle> {
        if Arc::as_ptr(&self.post) != Arc::as_ptr(&cap.post) {
            return Err(TableError::PostOfficeMismatch);
        }
        Ok(CapabilityHandle(self.import(cap.inner).0))
    }

    /// Helper function to directly insert a [Capability] into this table.
    pub(crate) fn import(&self, cap: Capability) -> CapabilityHandle {
        self.inner.lock().import(cap)
    }

    /// Import a [CapabilityRef] from any table directly into this table.
    ///
    /// Returns [TableError::PostOfficeMismatch] if the capability has different [PostOffice].
    pub fn import_ref(&self, cap: CapabilityRef<'_>) -> TableResult<CapabilityRef<'_>> {
        if !Arc::ptr_eq(&self.post, &cap.table.post) {
            return Err(TableError::PostOfficeMismatch);
        }
        let capability = cap
            .table
            .inner
            .lock()
            .entries
            .get(cap.handle.0)
            .ok_or(TableError::InvalidHandle)?
            .cap;
        let capability = self.inner.lock().import(capability);
        self.wrap_handle(capability)
    }

    /// Imports a table-less [Signal] to a table-local [ContextSignal].
    pub(crate) fn map_signal<'a>(&self, signal: RouteSignal<'a>) -> TableSignal<'a> {
        match signal {
            RouteSignal::Down { address } => TableSignal::Down {
                handle: self.import(Capability {
                    address,
                    perms: Permissions::empty(),
                }),
            },
            RouteSignal::Message { data, caps } => TableSignal::Message {
                data,
                caps: caps.iter().map(|cap| self.import(*cap)).collect(),
            },
        }
    }

    /// Imports a table-less [Signal] to a table-local [OwnedContextSignal].
    pub(crate) fn map_signal_owned(&self, signal: RouteSignal<'_>) -> OwnedTableSignal<'_> {
        match self.map_signal(signal) {
            TableSignal::Down { handle } => OwnedTableSignal::Down {
                handle: self.wrap_handle(handle).unwrap(),
            },
            TableSignal::Message { data, caps } => OwnedTableSignal::Message {
                data: data.to_owned(),
                caps: caps
                    .into_iter()
                    .map(|cap| self.wrap_handle(cap).unwrap())
                    .collect(),
            },
        }
    }

    /// Tests if a raw capability handle is valid within this table.
    pub fn is_valid(&self, handle: CapabilityHandle) -> bool {
        self.inner.lock().entries.contains(handle.0)
    }

    /// Wraps a raw capability handle in a Rust-friendly [CapabilityRef] struct.
    pub fn wrap_handle(&self, handle: CapabilityHandle) -> TableResult<CapabilityRef> {
        if !self.is_valid(handle) {
            return Err(TableError::InvalidHandle);
        }

        Ok(CapabilityRef {
            table: self,
            handle,
        })
    }

    /// Increments the reference count of a capability handle.
    ///
    /// If you'd prefer not to do this manually, try using [Table::wrap_handle]
    /// and relying on [CapabilityRef]'s `Clone` implementation instead.
    pub fn inc_ref(&self, handle: CapabilityHandle) -> TableResult<()> {
        self.inner
            .lock()
            .entries
            .get_mut(handle.0)
            .ok_or(TableError::InvalidHandle)?
            .ref_count += 1;

        Ok(())
    }

    /// Decrements the reference count of a capability handle. Removes this
    /// capability from this table if the reference count hits zero.
    ///
    /// If you'd prefer not to do this manually, try using [Table::wrap_handle]
    /// and relying on [CapabilityRef]'s `Drop` implementation instead.
    pub fn dec_ref(&self, handle: CapabilityHandle) -> TableResult<()> {
        let mut inner = self.inner.lock();

        let entry = inner
            .entries
            .get_mut(handle.0)
            .ok_or(TableError::InvalidHandle)?;

        if entry.ref_count > 1 {
            entry.ref_count -= 1;
        } else {
            let entry = inner.entries.remove(handle.0);
            inner.reverse_entries.remove(&entry.cap);
        }

        Ok(())
    }

    /// Retrieves the [Permissions] of a capability handle.
    pub fn get_permissions(&self, handle: CapabilityHandle) -> TableResult<Permissions> {
        self.inner
            .lock()
            .entries
            .get(handle.0)
            .ok_or(TableError::InvalidHandle)
            .map(|e| e.cap.perms)
    }

    /// Creates a new capability from an existing one with a subset of the original's [Permissions].
    ///
    /// Returns [TableError::PermissionDenied] if the permissions requested are
    /// not in the original's.
    pub fn demote(
        &self,
        handle: CapabilityHandle,
        perms: Permissions,
    ) -> TableResult<CapabilityHandle> {
        let mut inner = self.inner.lock();
        let entry = inner
            .entries
            .get(handle.0)
            .ok_or(TableError::InvalidHandle)?;
        let address = entry.cap.address;

        if !entry.cap.perms.contains(perms) {
            return Err(TableError::PermissionDenied);
        }

        let handle = inner.import(Capability { address, perms });
        Ok(handle)
    }

    /// Monitors a capability handle with a given mailbox.
    ///
    /// When the capability's route is closed, the mailbox will receive a
    /// down signal ([TableSignal::Down] or [OwnedTableSignal::Down])
    /// with a capability handle of a demoted version of the monitored
    /// capability *but with no [Permissions]*.
    ///
    /// Returns [TableError::PermissionDenied] if the capability does not have
    /// [Permissions::MONITOR].
    ///
    /// Returns [TableError::TableMismatch] if the mailbox belongs to a different [Table].
    pub fn monitor(&self, handle: CapabilityHandle, mailbox: &Mailbox) -> TableResult<()> {
        if !std::ptr::eq(mailbox.group.table, self) {
            return Err(TableError::TableMismatch);
        }

        let inner = self.inner.lock();
        let entry = inner
            .entries
            .get(handle.0)
            .ok_or(TableError::InvalidHandle)?;

        if !entry.cap.perms.contains(Permissions::MONITOR) {
            return Err(TableError::PermissionDenied);
        }

        self.post.monitor(&entry.cap.address, &mailbox.address);
        Ok(())
    }

    /// Links a mailbox group to the given capability.
    ///
    /// When the capability's route group dies, the given mailbox group will
    /// also be killed. Linking works the other way, too: when the mailbox
    /// group dies, the capability will also be killed.
    ///
    /// If either the mailbox group or the given capability are already dead,
    /// the other will be killed.
    ///
    /// Returns [TableError::PermissionDenied] if the capability does not have
    /// [Permissions::LINK].
    ///
    /// Returns [TableError::TableMismatch] if the mailbox group is using
    /// a different [Table].
    ///
    /// Does nothing if the capability and mailbox group are already linked.
    pub fn link(&self, handle: CapabilityHandle, group: &MailboxGroup) -> TableResult<()> {
        if !std::ptr::eq(group.table, self) {
            return Err(TableError::TableMismatch);
        }

        let inner = self.inner.lock();
        let entry = inner
            .entries
            .get(handle.0)
            .ok_or(TableError::InvalidHandle)?;

        if !entry.cap.perms.contains(Permissions::LINK) {
            return Err(TableError::PermissionDenied);
        }

        self.post.link(&entry.cap.address, &group.group);
        Ok(())
    }

    /// Unlinks a mailbox group from the given capability.
    ///
    /// Undoes [Self::link].
    ///
    /// Returns [TableError::PermissionDenied] if the capability does not have
    /// [Permissions::LINK].
    ///
    /// Returns [TableError::TableMismatch] if the mailbox group is using
    /// a different [Table].
    ///
    /// Does nothing if the capability and mailbox group are already unlinked.
    pub fn unlink(&self, handle: CapabilityHandle, group: &MailboxGroup) -> TableResult<()> {
        if !std::ptr::eq(group.table, self) {
            return Err(TableError::TableMismatch);
        }

        let inner = self.inner.lock();
        let entry = inner
            .entries
            .get(handle.0)
            .ok_or(TableError::InvalidHandle)?;

        if !entry.cap.perms.contains(Permissions::LINK) {
            return Err(TableError::PermissionDenied);
        }

        self.post.unlink(&entry.cap.address, &group.group);
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
    pub async fn send(
        &self,
        handle: CapabilityHandle,
        data: &[u8],
        caps: &[CapabilityHandle],
    ) -> TableResult<()> {
        // move into block to make this future Send
        let (address, mapped_caps) = {
            let inner = self.inner.lock();
            let entry = inner
                .entries
                .get(handle.0)
                .ok_or(TableError::InvalidHandle)?;

            if !entry.cap.perms.contains(Permissions::SEND) {
                return Err(TableError::PermissionDenied);
            }

            let mut mapped_caps = Vec::with_capacity(caps.len());
            for cap in caps.iter() {
                let entry = inner.entries.get(cap.0).ok_or(TableError::InvalidHandle)?;
                mapped_caps.push(entry.cap);
            }

            (entry.cap.address, mapped_caps)
        };

        self.post
            .send(
                &address,
                RouteSignal::Message {
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
    pub fn kill(&self, handle: CapabilityHandle) -> TableResult<()> {
        let inner = self.inner.lock();
        let entry = inner
            .entries
            .get(handle.0)
            .ok_or(TableError::InvalidHandle)?;

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
/// Cloning and dropping [CapabilityRef] automatically increments and
/// decrements the reference count of the handle index, so there's no need to
/// manually manage capability ownership while using this struct.
pub struct CapabilityRef<'a> {
    table: &'a Table,
    handle: CapabilityHandle,
}

impl<'a> Clone for CapabilityRef<'a> {
    fn clone(&self) -> Self {
        self.table.inc_ref(self.handle).unwrap();

        Self {
            table: self.table,
            handle: self.handle,
        }
    }
}

impl<'a> Debug for CapabilityRef<'a> {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        fmt.debug_tuple("CapabilityRef")
            .field(&self.handle)
            .finish()
    }
}

impl<'a> Drop for CapabilityRef<'a> {
    fn drop(&mut self) {
        self.table.dec_ref(self.handle).unwrap();
    }
}

impl<'a> CapabilityRef<'a> {
    /// Converts this handle wrapper into a raw handle index.
    ///
    /// You should call [Table::dec_ref] when you're done with this raw handle
    /// to avoid resource leaks.
    pub fn into_handle(self) -> CapabilityHandle {
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

    /// Creates a new [CapabilityRef] with a subset of the [Permissions] of this one.
    ///
    /// Returns [TableError::PermissionDenied] if the permissions requested are
    /// not in this one's.
    pub fn demote(&self, perms: Permissions) -> TableResult<Self> {
        Ok(Self {
            table: self.table,
            handle: self.table.demote(self.handle, perms)?,
        })
    }

    /// Monitors this capability handle from a given mailbox.
    ///
    /// When this capability's route is closed, the mailbox will receive an
    /// down signal ([TableSignal::Down] or [OwnedTableSignal::Down])
    /// with a capability handle of a demoted version of this capability *but
    /// with no [Permissions]*.
    ///
    /// Returns [TableError::PermissionDenied] if this capability does not have
    /// [Permissions::MONITOR].
    pub fn monitor(&self, mailbox: &Mailbox<'a>) -> TableResult<()> {
        self.table.monitor(self.handle, mailbox)
    }

    /// Sends a message to this capability handle.
    ///
    /// This function is async because zero-copy sending of signals needs to
    /// wait for the receiver to finish consuming the sent data before returning
    /// in order to safely capture the lifetime of the data.
    ///
    /// Returns [TableError::TableMismatch] if any capabilities have a different [Table].
    pub async fn send(&self, data: &[u8], caps: &[&CapabilityRef<'_>]) -> TableResult<()> {
        let mut mapped_caps = Vec::with_capacity(caps.len());
        for cap in caps.iter() {
            if !std::ptr::eq(cap.table, self.table) {
                return Err(TableError::TableMismatch);
            }
            mapped_caps.push(cap.handle);
        }

        self.table.send(self.handle, data, &mapped_caps).await
    }

    /// Kills this capability handle.
    ///
    /// Returns [TableError::PermissionDenied] if this capability does not have
    /// [Permissions::KILL].
    pub fn kill(&self) -> TableResult<()> {
        self.table.kill(self.handle)
    }
}

/// A signal that has been received through [Mailbox::recv] or
/// [Mailbox::try_recv] and has been imported into a [Table].
///
/// This enum is non-owning and facilitates zero-copy signal-sending. For
/// low-level scripting integrations or performance-sensitive signal handling,
/// this is fine. If you're not doing any of that, you probably want to use
/// [Mailbox::recv_owned] and [Mailbox::try_recv_owned] to get an
/// [OwnedTableSignal] instead.
///
/// Senders of non-owning signals wait for signals to be handled since they own
/// the signals' memory. Finish dealing with this signal in as quick and as
/// constant of a time as possible to avoid creating timing attack
/// vulnerabilities.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TableSignal<'a> {
    /// A notification that a capability monitored by this mailbox has been killed.
    Down {
        /// An owning handle of a demoted version of the capability that was
        /// originally monitored but with no [Permissions].
        handle: CapabilityHandle,
    },

    /// A message from another process.
    Message {
        /// This message's data as a raw byte array.
        data: &'a [u8],

        /// The capabilities sent in this message.
        caps: Vec<CapabilityHandle>,
    },
}

/// An owned signal that has been received through [Mailbox::recv_owned] or
/// [Mailbox::try_recv_owned] and has been imported into a [Table].
///
/// A higher-level, owning version of [TableSignal]. The generic lifetime
/// parameter of this object is tied to the lifetime of the current table and
/// not to the receiving of the message.
#[derive(Clone, Debug)]
pub enum OwnedTableSignal<'a> {
    /// A notification that a capability monitored by this mailbox has been killed.
    Down {
        /// An owning handle of a demoted version of the capability that was
        /// originally monitored but with no [Permissions].
        handle: CapabilityRef<'a>,
    },

    /// A message from another process.
    Message {
        /// This message's data as a raw byte array.
        data: Vec<u8>,

        /// The capabilities sent in this message.
        caps: Vec<CapabilityRef<'a>>,
    },
}

/// A factory for [Mailbox]es that belong to the same route group.
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
    group: Arc<RouteGroup>,
}

impl<'a> MailboxGroup<'a> {
    /// Creates a new mailbox group for the given [Table].
    pub fn new(table: &'a Table) -> Self {
        Self {
            table,
            group: Arc::new(RouteGroup::default()),
        }
    }

    /// Creates a new mailbox. Returns `None` if this mailbox group has been killed.
    pub fn create_mailbox(&self) -> Option<Mailbox<'_>> {
        let (tx, rx) = channel();
        let address = self.table.post.insert(tx, self.group.clone())?;

        Some(Mailbox {
            group: self,
            address,
            rx,
        })
    }

    /// Retrieves this mailbox group's underlying route group.
    pub fn get_route_group(&self) -> &Arc<RouteGroup> {
        &self.group
    }

    /// Kills this mailbox group.
    pub fn kill(&self) {
        self.group.kill(&self.table.post);
    }

    /// Checks if this mailbox group has been killed.
    pub fn poll_dead(&self) -> bool {
        self.group.is_dead()
    }
}

/// A receiver for [TableSignals][TableSignal].
///
/// Processes create mailboxes in order to receive signals from other processes.
/// A process can close a mailbox or a mailbox can be killed by other processes
/// using [Permissions::KILL] on a mailbox's capability. When a mailbox is
/// killed, all of the other mailboxes in its [MailboxGroup] are killed as well.
///
/// To get started using mailboxes, see [Mailbox::recv]. If you don't need to
/// process zero-copy signals, you can call [Mailbox::recv_owned] instead.
/// [Mailbox::try_recv] and [Mailbox::try_recv_owned] poll the mailbox for new
/// signals without blocking.
pub struct Mailbox<'a> {
    group: &'a MailboxGroup<'a>,
    address: RouteAddress,
    rx: Receiver<OwnedRouteSignal>,
}

impl<'a> Drop for Mailbox<'a> {
    fn drop(&mut self) {
        self.group.table.post.close(&self.address);
    }
}

impl<'a> Mailbox<'a> {
    /// Receives a single signal from this mailbox.
    ///
    /// [TableSignal] is non-owning, so this function takes a closure to map a
    /// temporary [TableSignal] into types of a larger lifetime.
    ///
    /// Returns `None` when this mailbox's process has been killed.
    pub async fn recv<T>(&self, mut f: impl for<'b> FnMut(TableSignal<'b>) -> T) -> Option<T> {
        self.rx
            .recv(|signal| {
                let signal = self.group.table.map_signal(signal);
                f(signal)
            })
            .await
            .ok()
    }

    /// Receives a [OwnedTableSignal].
    ///
    /// Returns `None` when this mailbox's process has been killed.
    pub async fn recv_owned(&self) -> Option<OwnedTableSignal<'a>> {
        self.rx
            .recv(|signal| self.group.table.map_signal_owned(signal))
            .await
            .ok()
    }

    /// Polls this mailbox for any currently available signals.
    ///
    /// [TableSignal] is non-owning, so this function takes a lambda to map
    /// a temporary [TableSignal] into types of a larger lifetime.
    ///
    /// Returns:
    /// - `Some(Some(t))` when there was a signal available and it was mapped by the lambda.
    /// - `Some(None)` when there was not a signal available.
    /// - `None` when this mailbox's process has been killed.
    pub fn try_recv<T>(
        &self,
        mut f: impl for<'b> FnMut(TableSignal<'b>) -> T,
    ) -> Option<Option<T>> {
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
    pub fn try_recv_owned(&self) -> Option<Option<OwnedTableSignal<'a>>> {
        let result = self
            .rx
            .try_recv(|signal| self.group.table.map_signal_owned(signal));

        match result {
            Ok(signal) => Some(Some(signal)),
            Err(flume::TryRecvError::Empty) => Some(None),
            Err(flume::TryRecvError::Disconnected) => None,
        }
    }

    /// Exports a [CapabilityRef] to a [Table].
    pub fn export_to<'b>(
        &self,
        perms: Permissions,
        table: &'b Table,
    ) -> TableResult<CapabilityRef<'b>> {
        if !Arc::ptr_eq(&self.group.table.post, &table.post) {
            return Err(TableError::PostOfficeMismatch);
        }

        let handle = table.import(Capability {
            address: self.address,
            perms,
        });

        Ok(CapabilityRef { table, handle })
    }

    /// Exports a [CapabilityRef] to the current mailbox's [Table].
    pub fn export(&self, perms: Permissions) -> TableResult<CapabilityRef<'a>> {
        self.export_to(perms, self.group.table)
    }

    /// Exports an [OwnedCapability] from this mailbox.
    ///
    /// This method is intended to be used to import a capability from a mailbox into a [Table].
    pub fn export_owned(&self, perms: Permissions) -> OwnedCapability {
        OwnedCapability {
            inner: Capability {
                address: self.address,
                perms,
            },
            post: self.group.table.post.clone(),
        }
    }
}
