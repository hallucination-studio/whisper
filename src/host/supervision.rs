//! Independent reader/writer lifecycle supervision and cleanup.

use super::*;
pub(super) fn supervise(builder: HostBuilder, context: SupervisorContext) {
    let SupervisorContext {
        socket,
        threads,
        replay_snapshot,
        stop,
        completion,
        rejections,
        ready_sender: ready,
    } = context;
    let overflow = Arc::new(OverflowSummary { count: AtomicU64::new(0) });
    let (ingress_sender, ingress_receiver) = mpsc::sync_channel(builder.ingress_capacity);
    let (worker_exit_sender, worker_exit_receiver) = mpsc::channel();
    let (writer_ready_sender, writer_ready_receiver) = mpsc::sync_channel(1);
    let writer_overflow = Arc::clone(&overflow);
    let writer_rejections = Arc::clone(&rejections);
    let writer_exit = worker_exit_sender.clone();
    let routes = Arc::new(builder.routes);
    let writer_config = WriterConfig {
        database_path: builder.store.database_path(),
        replay_snapshot,
        deployment: builder.deployment.clone(),
        routes: Arc::clone(&routes),
        clock: Arc::clone(&builder.clock),
    };
    let writer = threads.spawn(
        "whisper-fact-writer",
        Box::new(move || {
            let mut exit = WorkerExitNotifier::new("writer", writer_exit);
            let result = writer_loop(
                writer_config,
                ingress_receiver,
                &writer_overflow,
                &writer_rejections,
                writer_ready_sender,
            );
            exit.complete(result);
        }),
    );
    let Ok(writer) = writer else {
        let error = HostError::message("could not spawn the Store writer");
        let _ = ready.send(Err(error));
        finish_completion(&completion, Some("could not spawn the Store writer".to_owned()));
        return;
    };
    match writer_ready_receiver.recv() {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            let message = error.to_string();
            let _ = ready.send(Err(error));
            let _ = writer.join();
            finish_completion(&completion, Some(message));
            return;
        }
        Err(_) => {
            let message = "Store writer exited during startup".to_owned();
            let _ = ready.send(Err(HostError::worker(message.clone())));
            let _ = writer.join();
            finish_completion(&completion, Some(message));
            return;
        }
    }

    let reader_stop = Arc::clone(&stop);
    let reader_overflow = Arc::clone(&overflow);
    let reader_exit = worker_exit_sender;
    let reader_config = ReaderConfig { socket, routes, clock: Arc::clone(&builder.clock) };
    let reader = threads.spawn(
        "whisper-udp-reader",
        Box::new(move || {
            let mut exit = WorkerExitNotifier::new("reader", reader_exit);
            let result = reader_loop(
                reader_config,
                ingress_sender,
                &reader_overflow,
                &rejections,
                &reader_stop,
            );
            exit.complete(result);
        }),
    );
    let Ok(reader) = reader else {
        stop.store(true, Ordering::Release);
        let _ = writer.join();
        let error = HostError::message("could not spawn the UDP reader");
        let _ = ready.send(Err(error));
        finish_completion(&completion, Some("could not spawn the UDP reader".to_owned()));
        return;
    };
    if ready.send(Ok(())).is_err() {
        stop.store(true, Ordering::Release);
    }

    let first_exit = loop {
        if stop.load(Ordering::Acquire) {
            break None;
        }
        match worker_exit_receiver.recv_timeout(SOCKET_POLL_INTERVAL) {
            Ok(exit) => break Some(exit),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break None,
        }
    };
    stop.store(true, Ordering::Release);
    let reader_join = reader.join();
    let writer_join = writer.join();
    let mut failure = first_exit
        .and_then(|(worker, result)| result.err().map(|error| format!("{worker}: {error}")));
    if reader_join.is_err() {
        failure.get_or_insert_with(|| "UDP reader panicked".to_owned());
    }
    if writer_join.is_err() {
        failure.get_or_insert_with(|| "Store writer panicked".to_owned());
    }
    drop(builder.store);
    finish_completion(&completion, failure);
}
