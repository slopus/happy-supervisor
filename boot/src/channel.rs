//! The lines boot and the supervisor exchange over the supervisor's stdin and stdout
//! (docs/boot.md, The channel): one JSON object per line each way.

use serde::{Deserialize, Serialize};

/// What boot is doing, sent to the supervisor at start and on every change, which reports it to
/// the control plane as `node.boot` and NodeInfo `boot`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    /// This boot's own version, which never changes on a node.
    pub boot_version: &'static str,
    /// The version running, or starting when `state` is `starting`.
    pub running: Option<String>,
    /// The version kept to go back to.
    pub previous: Option<String>,
    /// The version last asked for, until it runs or fails.
    pub target: Option<String>,
    pub state: State,
    /// Why the last change failed, with `state` `failed`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// How many times `running` was restarted after it exited on its own.
    pub restarts: u32,
    /// How it exited last, as `exited with code 1` or `killed by signal 9`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_exit: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum State {
    Idle,
    Downloading,
    Verifying,
    Starting,
    Failed,
}

/// A line to the supervisor.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ToSupervisor<'a> {
    Status(&'a Status),
}

/// A line from the supervisor.
#[derive(Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FromSupervisor {
    /// Run `version` instead (`node.upgrade`).
    Upgrade { version: String },
    /// The supervisor's first session opened: it is healthy.
    Connected {},
}

impl ToSupervisor<'_> {
    pub fn line(&self) -> String {
        let mut line = serde_json::to_string(self).expect("the line serializes");
        line.push('\n');
        line
    }
}

impl FromSupervisor {
    /// `None` for a line that is not one: the supervisor's stdout may carry anything else too.
    pub fn parse(line: &str) -> Option<FromSupervisor> {
        serde_json::from_str(line).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines() {
        let status = Status {
            boot_version: "0.1.0",
            running: Some("0.2.9".into()),
            previous: Some("0.2.8".into()),
            target: Some("0.3.0".into()),
            state: State::Failed,
            error: Some("0.3.0 did not connect within 120 s".into()),
            restarts: 1,
            last_exit: Some("exited with code 1".into()),
        };
        assert_eq!(
            ToSupervisor::Status(&status).line(),
            r#"{"status":{"bootVersion":"0.1.0","running":"0.2.9","previous":"0.2.8","target":"0.3.0","state":"failed","error":"0.3.0 did not connect within 120 s","restarts":1,"lastExit":"exited with code 1"}}"#
                .to_owned()
                + "\n"
        );
        let idle = Status {
            target: None,
            state: State::Idle,
            error: None,
            restarts: 0,
            last_exit: None,
            ..status
        };
        assert_eq!(
            ToSupervisor::Status(&idle).line(),
            r#"{"status":{"bootVersion":"0.1.0","running":"0.2.9","previous":"0.2.8","target":null,"state":"idle","restarts":0}}"#
                .to_owned()
                + "\n"
        );
        assert_eq!(
            FromSupervisor::parse(r#"{"upgrade":{"version":"0.3.0"}}"#),
            Some(FromSupervisor::Upgrade {
                version: "0.3.0".into()
            })
        );
        assert_eq!(
            FromSupervisor::parse(r#"{"connected":{}}"#),
            Some(FromSupervisor::Connected {})
        );
        assert_eq!(FromSupervisor::parse("listening 127.0.0.1:1"), None);
    }
}
