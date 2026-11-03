// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026, Jaehun Lee
//! Host-side LibAFL TCP broker shared by independent QEMU guests.

use std::{error::Error, net::TcpListener, path::PathBuf, process::ExitCode};

use libafl::{events::tcp::TcpEventBroker, inputs::BytesInput, monitors::SimpleMonitor};

fn run() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args_os();
    let _program = args.next();
    let port_file = PathBuf::from(args.next().ok_or("expected PORT_FILE")?);
    if args.next().is_some() {
        return Err("expected only PORT_FILE".into());
    }

    // QEMU's user-mode network exposes the host loopback to the guest at 10.0.2.2.
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    listener.set_nonblocking(true)?;
    let port = listener.local_addr()?.port();
    let monitor = SimpleMonitor::new(|message| println!("{message}"));
    let mut broker = TcpEventBroker::<BytesInput, _>::with_listener(listener, monitor);
    std::fs::write(port_file, format!("{port}\n"))?;
    println!("FUZZ_BROKER_READY port={port}");
    broker.broker_loop()?;
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("FUZZ_BROKER_ERROR={error}");
            ExitCode::from(2)
        }
    }
}
