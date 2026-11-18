//! Process groups and Job Objects for spawned commands. Owned by the exec track.

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;
