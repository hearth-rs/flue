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
            s == TableSignal::Message {
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
            s == TableSignal::Message {
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
                s == TableSignal::Message {
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
            s == TableSignal::Message {
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

    let s_cap = CapabilityRef {
        table: &table,
        handle: s_handle,
    };

    s_cap.link(&object).unwrap();
    s_cap.kill().unwrap();

    let expected = TableSignal::Unlink {
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

    let expected = TableSignal::Unlink {
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

    let s_cap = CapabilityRef {
        table: &table,
        handle: s_handle,
    };

    s_cap.kill().unwrap();
    s_cap.link(&object).unwrap();

    let expected = TableSignal::Unlink {
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

    let expected = TableSignal::Unlink {
        handle: s_cap.demote(Permissions::empty()).unwrap().handle,
    };

    object.recv(move |s| assert_eq!(s, expected)).await.unwrap();
}

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
