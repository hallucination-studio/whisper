//! Sole-writer transaction A and durable replay-state persistence.

use super::*;
pub(super) fn writer_loop(
    config: WriterConfig,
    ingress: mpsc::Receiver<AdmittedDatagram>,
    overflow: &OverflowSummary,
    rejections: &Mutex<VecDeque<RejectedDatagram>>,
    ready: mpsc::SyncSender<Result<(), HostError>>,
) -> Result<(), HostError> {
    let startup = match load_replay_states_from_path(
        config.replay_snapshot.database_path(),
        &config.database_path,
        &config.deployment,
        &config.routes,
    ) {
        Ok(startup) => startup,
        Err(error) => {
            let _ = ready.send(Err(error));
            return Ok(());
        }
    };
    let mut connection = match Connection::open_with_flags(
        &config.database_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    ) {
        Ok(connection) => connection,
        Err(error) => {
            let error = HostError::database_at(&config.database_path, error);
            let _ = ready.send(Err(error));
            return Ok(());
        }
    };
    if startup.provision
        && let Err(error) =
            provision_replay_states(&mut connection, &config.routes, &startup.states)
    {
        let error = HostError::database_at(&config.database_path, error);
        let _ = ready.send(Err(error));
        return Ok(());
    }
    if let Err(error) =
        connection.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;")
    {
        let error = HostError::database_at(&config.database_path, error);
        let _ = ready.send(Err(error));
        return Ok(());
    }
    let mut replay = startup.states;
    if ready.send(Ok(())).is_err() {
        return Ok(());
    }

    loop {
        persist_overflow(&mut connection, &config.database_path, overflow, config.clock.as_ref())?;
        match ingress.recv_timeout(SOCKET_POLL_INTERVAL) {
            Ok(item) => persist_admitted(
                &mut connection,
                &config.database_path,
                &config.routes,
                &mut replay,
                rejections,
                item,
            )?,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    persist_overflow(&mut connection, &config.database_path, overflow, config.clock.as_ref())?;
    connection
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .map_err(|error| HostError::database_at(&config.database_path, error))?;
    Ok(())
}

fn load_replay_states_from_path(
    snapshot_path: &Path,
    store_path: &Path,
    deployment: &DeploymentId,
    routes: &[NativeFrameRoute],
) -> Result<ReplayStartup, HostError> {
    let connection = Connection::open_with_flags(
        snapshot_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|error| HostError::database_at(store_path, error))?;
    load_replay_states(&connection, store_path, deployment, routes)
}

fn load_replay_states(
    connection: &Connection,
    path: &Path,
    deployment: &DeploymentId,
    routes: &[NativeFrameRoute],
) -> Result<ReplayStartup, HostError> {
    let configured: u8 = connection
        .query_row(
            "SELECT admission_configured FROM store_identity WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .map_err(|error| HostError::database_at(path, error))?;
    let row_count: usize = connection
        .query_row("SELECT count(*) FROM replay_windows", [], |row| row.get(0))
        .map_err(|error| HostError::database_at(path, error))?;
    if configured == 0 && row_count != 0 {
        return Err(HostError::message_at(
            "validate retained replay state",
            path,
            "unprovisioned Store contains replay state",
        ));
    }
    if configured == 1 && row_count != routes.len() {
        return Err(HostError::message_at(
            "validate retained replay state",
            path,
            "persisted replay route set does not match configuration",
        ));
    }
    if configured > 1 {
        return Err(HostError::message_at(
            "validate retained replay state",
            path,
            "persisted admission configuration marker is invalid",
        ));
    }
    let states = routes
        .iter()
        .map(|route| {
            let identity = derive_replay_window_identity(
                deployment.as_str(),
                route.device_id.get(),
                route.key_epoch.get(),
                &route.key,
            )
            .map_err(|error| HostError::replay_identity(path, error))?;
            let persisted: Option<(Vec<u8>, u16, Vec<u8>)> = connection
                .query_row(
                    "SELECT identity, window_packets, state FROM replay_windows
                     WHERE device_id = ?1 AND key_epoch = ?2",
                    params![
                        route.device_id.get().to_be_bytes(),
                        route.key_epoch.get().to_be_bytes()
                    ],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()
                .map_err(|error| HostError::database_at(path, error))?;
            let admission = match persisted {
                Some((stored_identity, stored_window, state)) => {
                    if configured == 0
                        || stored_identity.as_slice() != identity.as_bytes()
                        || stored_window != route.limits.replay_window_packets.get()
                    {
                        return Err(HostError::message_at(
                            "validate retained replay state",
                            path,
                            "persisted replay identity or window does not match configuration",
                        ));
                    }
                    let admission = ReplayAdmission::decode_state(&state)
                        .map_err(|error| HostError::replay_state(path, error))?;
                    if admission.window_packets() != stored_window {
                        return Err(HostError::message_at(
                            "validate retained replay state",
                            path,
                            "persisted replay state window does not match configuration",
                        ));
                    }
                    admission
                }
                None if configured == 0 => {
                    ReplayAdmission::new(route.limits.replay_window_packets.get())
                        .map_err(|error| HostError::replay_state(path, error))?
                }
                None => {
                    return Err(HostError::message_at(
                        "validate retained replay state",
                        path,
                        "configured replay route is missing",
                    ));
                }
            };
            Ok(ReplayWriterState { identity: *identity.as_bytes(), admission })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ReplayStartup { states, provision: configured == 0 })
}

fn provision_replay_states(
    connection: &mut Connection,
    routes: &[NativeFrameRoute],
    states: &[ReplayWriterState],
) -> Result<(), rusqlite::Error> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    for (route, state) in routes.iter().zip(states) {
        transaction.execute(
            "INSERT INTO replay_windows
                 (device_id, key_epoch, identity, window_packets, state)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                route.device_id.get().to_be_bytes(),
                route.key_epoch.get().to_be_bytes(),
                state.identity,
                route.limits.replay_window_packets.get(),
                state.admission.encode_state(),
            ],
        )?;
    }
    transaction
        .execute("UPDATE store_identity SET admission_configured = 1 WHERE singleton = 1", [])?;
    transaction.commit()
}

fn persist_admitted(
    connection: &mut Connection,
    path: &Path,
    routes: &[NativeFrameRoute],
    replay: &mut [ReplayWriterState],
    rejections: &Mutex<VecDeque<RejectedDatagram>>,
    item: AdmittedDatagram,
) -> Result<(), HostError> {
    let route = &routes[item.route_index];
    let state = &mut replay[item.route_index];
    let mut next = state.admission.clone();
    let previous =
        match (state.admission.boot_generation(), state.admission.maximum_message_sequence()) {
            (Some(boot), Some(sequence)) if boot == item.header.boot_generation() => Some(sequence),
            _ => None,
        };
    if next.admit(item.header.boot_generation(), item.header.message_seq())
        == ReplayDecision::Rejected
    {
        record_rejection(rejections, item.peer, RejectReason::Replay);
        return Ok(());
    }
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| HostError::database_at(path, error))?;
    let digest: [u8; 32] = Sha256::digest(&item.bytes).into();
    transaction
        .execute(
            "INSERT INTO raw_facts (
                 digest, received_utc_ns, peer, device_id, key_epoch,
                 boot_generation, message_sequence, kind, datagram
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                digest,
                item.received_utc_ns,
                item.peer.to_string(),
                item.header.device_id().to_be_bytes(),
                item.header.key_epoch().to_be_bytes(),
                item.header.boot_generation().to_be_bytes(),
                item.header.message_seq().to_be_bytes(),
                item.header.kind_byte(),
                &item.bytes,
            ],
        )
        .map_err(|error| HostError::database_at(path, error))?;
    persist_sequence_discontinuity(&transaction, path, previous, &item)?;
    transaction
        .execute(
            "UPDATE replay_windows SET state = ?1
             WHERE device_id = ?2 AND key_epoch = ?3 AND identity = ?4 AND window_packets = ?5",
            params![
                next.encode_state(),
                route.device_id.get().to_be_bytes(),
                route.key_epoch.get().to_be_bytes(),
                state.identity,
                route.limits.replay_window_packets.get(),
            ],
        )
        .map_err(|error| HostError::database_at(path, error))?;
    transaction.commit().map_err(|error| HostError::database_at(path, error))?;
    state.admission = next;
    Ok(())
}

fn persist_sequence_discontinuity(
    connection: &Connection,
    path: &Path,
    previous: Option<u64>,
    item: &AdmittedDatagram,
) -> Result<(), HostError> {
    let Some(previous) = previous else {
        return Ok(());
    };
    let current = item.header.message_seq();
    let (kind, first, last) = if current > previous.saturating_add(1) {
        ("sequence_gap_observed", previous + 1, current - 1)
    } else if current < previous {
        ("reordered_arrival", current, current)
    } else {
        return Ok(());
    };
    connection
        .execute(
            "INSERT INTO raw_losses (
                 observed_utc_ns, kind, count, device_id, boot_generation,
                 first_sequence, last_sequence
             ) VALUES (?1, ?2, 1, ?3, ?4, ?5, ?6)",
            params![
                item.received_utc_ns,
                kind,
                item.header.device_id().to_be_bytes(),
                item.header.boot_generation().to_be_bytes(),
                first.to_be_bytes(),
                last.to_be_bytes(),
            ],
        )
        .map_err(|error| HostError::database_at(path, error))?;
    Ok(())
}

fn persist_overflow(
    connection: &mut Connection,
    path: &Path,
    overflow: &OverflowSummary,
    clock: &dyn Clock,
) -> Result<(), HostError> {
    let count = overflow.count.swap(0, Ordering::AcqRel);
    if count == 0 {
        return Ok(());
    }
    let count = i64::try_from(count).unwrap_or(i64::MAX);
    connection
        .execute(
            "INSERT INTO raw_losses (observed_utc_ns, kind, count)
             VALUES (?1, 'ingress_queue_overflow', ?2)",
            params![utc_now_ns(clock)?, count],
        )
        .map_err(|error| HostError::database_at(path, error))?;
    Ok(())
}
