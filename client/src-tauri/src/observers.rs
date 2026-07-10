//! Bridges from the core's push-only observer callbacks to `tauri::ipc::Channel`s.
//!
//! These fire on the core's background runtime threads, so they must stay
//! non-blocking — they just forward the bytes/events into the channel bound to
//! the originating `invoke` call. The frontend feeds the bytes straight into
//! xterm.js (PTY) or its exec/broadcast/transfer views.

use serde::Serialize;
use tauri::ipc::Channel;
use unissh_ffi::{BroadcastObserver, ExecObserver, SessionObserver, SftpProgressObserver};

#[derive(Clone, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum TermEvent {
    Data { bytes: Vec<u8> },
    Close { exit: i32 },
}

pub struct ChannelSessionObserver {
    pub chan: Channel<TermEvent>,
}
impl SessionObserver for ChannelSessionObserver {
    fn on_data(&self, data: Vec<u8>) {
        let _ = self.chan.send(TermEvent::Data { bytes: data });
    }
    fn on_close(&self, exit_status: i32) {
        let _ = self.chan.send(TermEvent::Close { exit: exit_status });
    }
}

#[derive(Clone, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum ExecEvent {
    Stdout { bytes: Vec<u8> },
    Stderr { bytes: Vec<u8> },
    Exit { exit: i32 },
}

pub struct ChannelExecObserver {
    pub chan: Channel<ExecEvent>,
}
impl ExecObserver for ChannelExecObserver {
    fn on_stdout(&self, data: Vec<u8>) {
        let _ = self.chan.send(ExecEvent::Stdout { bytes: data });
    }
    fn on_stderr(&self, data: Vec<u8>) {
        let _ = self.chan.send(ExecEvent::Stderr { bytes: data });
    }
    fn on_exit(&self, exit_status: i32) {
        let _ = self.chan.send(ExecEvent::Exit { exit: exit_status });
    }
}

#[derive(Clone, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum BroadcastEvent {
    Data { index: u32, bytes: Vec<u8> },
    Close { index: u32, exit: i32 },
}

pub struct ChannelBroadcastObserver {
    pub chan: Channel<BroadcastEvent>,
}
impl BroadcastObserver for ChannelBroadcastObserver {
    fn on_data(&self, host_index: u32, data: Vec<u8>) {
        let _ = self.chan.send(BroadcastEvent::Data {
            index: host_index,
            bytes: data,
        });
    }
    fn on_close(&self, host_index: u32, exit_status: i32) {
        let _ = self.chan.send(BroadcastEvent::Close {
            index: host_index,
            exit: exit_status,
        });
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProgressEvent {
    pub transferred: u64,
    pub total: u64,
}

pub struct ChannelSftpProgress {
    pub chan: Channel<ProgressEvent>,
}
impl SftpProgressObserver for ChannelSftpProgress {
    fn on_progress(&self, transferred: u64, total: u64) {
        let _ = self.chan.send(ProgressEvent { transferred, total });
    }
}
