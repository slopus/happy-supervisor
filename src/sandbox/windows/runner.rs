//! The runner: `<exe> __sandbox runner` as the leased account (module docs, step 2).

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Write as _;
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};

use windows_sys::Win32::Foundation::{HANDLE, HANDLE_FLAG_INHERIT, SetHandleInformation};
use windows_sys::Win32::Security::{ImpersonateLoggedOnUser, RevertToSelf};
use windows_sys::Win32::System::Threading::{
    CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW, GetExitCodeProcess, INFINITE,
    PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOW, WaitForSingleObject,
};

use super::broker::{RunnerJob, raw_stdin, read_frame, report};
use super::token::{self, TokenSpec};
use super::win::{check, owned, wide};
use crate::error::{Error, Result};
use crate::fs::FsRequest;
use crate::helper::{EXIT_BAD_JOB, JobOp};
use crate::protocol::{AbsPath, Argv};

pub(super) fn main() -> ! {
    let job: RunnerJob = match raw_stdin()
        .map_err(Error::from)
        .and_then(|mut stdin| read_frame(&mut stdin))
    {
        Ok(job) => job,
        Err(err) => {
            eprintln!("happy-supervisor __sandbox runner: {err}");
            std::process::exit(EXIT_BAD_JOB)
        }
    };
    // SAFETY: the broker duplicated this handle into us and nothing else owns it.
    let status = (job.status != 0).then(|| unsafe { File::from_raw_handle(job.status as HANDLE) });
    match &job.op {
        JobOp::Exec { argv, cwd, env } => match spawn(&job.token, argv, cwd, env) {
            Ok(process) => {
                drop(status);
                std::process::exit(wait(&process) as i32)
            }
            Err(err) => report(&job.op, status, err),
        },
        JobOp::Fs(request) => {
            let frame = crate::helper::encode_fs_reply(perform(&job.token, request));
            let mut stdout = std::io::stdout().lock();
            let written = stdout.write_all(&frame).and_then(|()| stdout.flush());
            std::process::exit(if written.is_ok() { 0 } else { 1 })
        }
    }
}

/// Performs the file operation on this thread, impersonating the command's token.
fn perform(spec: &TokenSpec, request: &FsRequest) -> Result<crate::fs::FsResponse> {
    let token = token::impersonation(&token::restricted(&token::own()?, spec)?)?;
    // SAFETY: an impersonation token of our own account.
    check(unsafe { ImpersonateLoggedOnUser(token.as_raw_handle() as HANDLE) })?;
    let result = crate::fs::perform(request);
    // SAFETY: ends the impersonation started above.
    unsafe { RevertToSelf() };
    result
}

fn spawn(
    spec: &TokenSpec,
    argv: &Argv,
    cwd: &AbsPath,
    env: &BTreeMap<String, String>,
) -> Result<OwnedHandle> {
    let token = token::restricted(&token::own()?, spec)?;
    let stdio = [
        std::io::stdin().as_raw_handle(),
        std::io::stdout().as_raw_handle(),
        std::io::stderr().as_raw_handle(),
    ];
    for handle in stdio {
        // SAFETY: our own std handles. Only they are inheritable here: every other handle
        // this process holds was opened or duplicated without inheritance.
        check(unsafe {
            SetHandleInformation(handle as HANDLE, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)
        })?;
    }
    let startup = STARTUPINFOW {
        cb: size_of::<STARTUPINFOW>() as u32,
        dwFlags: STARTF_USESTDHANDLES,
        hStdInput: stdio[0] as HANDLE,
        hStdOutput: stdio[1] as HANDLE,
        hStdError: stdio[2] as HANDLE,
        ..Default::default()
    };
    let mut command_line = wide(command_line(argv.as_slice()));
    let environment = environment_block(env);
    let mut info = PROCESS_INFORMATION::default();
    // SAFETY: a restricted copy of our own token; every string and block lives across the
    // call; the inherited handles are our std handles.
    let created = check(unsafe {
        CreateProcessAsUserW(
            token.as_raw_handle() as HANDLE,
            wide(argv.program()).as_ptr(),
            command_line.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1,
            CREATE_UNICODE_ENVIRONMENT,
            environment.as_ptr().cast(),
            wide(cwd.as_path()).as_ptr(),
            &startup,
            &mut info,
        )
    });
    if let Err(err) = created {
        let message = format!("cannot run {}: {err}", argv.program());
        return Err(Error::new(Error::from(err).kind, message));
    }
    // SAFETY: fresh handles from CreateProcessAsUserW.
    let (process, _thread) = unsafe { (owned(info.hProcess), owned(info.hThread)) };
    Ok(process)
}

fn wait(process: &OwnedHandle) -> u32 {
    let handle = process.as_raw_handle() as HANDLE;
    let mut code = 1u32;
    // SAFETY: the process handle is open.
    unsafe {
        WaitForSingleObject(handle, INFINITE);
        GetExitCodeProcess(handle, &mut code);
    }
    code
}

/// `argv` joined as the C runtime splits a command line back into arguments.
fn command_line(argv: &[String]) -> String {
    argv.iter()
        .map(|arg| quote(arg))
        .collect::<Vec<_>>()
        .join(" ")
}

fn quote(arg: &str) -> String {
    if !arg.is_empty() && !arg.contains([' ', '\t', '\n', '\x0b', '"']) {
        return arg.to_string();
    }
    let mut quoted = String::from('"');
    let mut backslashes = 0;
    for ch in arg.chars() {
        match ch {
            '\\' => backslashes += 1,
            '"' => {
                quoted.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
                quoted.push('"');
                backslashes = 0;
            }
            _ => {
                quoted.extend(std::iter::repeat_n('\\', backslashes));
                quoted.push(ch);
                backslashes = 0;
            }
        }
    }
    quoted.extend(std::iter::repeat_n('\\', backslashes * 2));
    quoted.push('"');
    quoted
}

/// `KEY=value\0` for each variable, sorted without case as Windows expects, then `\0`.
fn environment_block(env: &BTreeMap<String, String>) -> Vec<u16> {
    let mut vars: Vec<(&String, &String)> = env.iter().collect();
    vars.sort_by_key(|(key, _)| key.to_uppercase());
    let mut block: Vec<u16> = vars
        .into_iter()
        .flat_map(|(key, value)| {
            format!("{key}={value}\0")
                .encode_utf16()
                .collect::<Vec<_>>()
        })
        .collect();
    if block.is_empty() {
        block.push(0);
    }
    block.push(0);
    block
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arguments_survive_the_c_runtime_rules() {
        assert_eq!(
            command_line(&[
                r"C:\Windows\System32\cmd.exe".into(),
                "/c".into(),
                "echo hi there".into(),
                "".into(),
                r#"say "x""#.into(),
                r"C:\dir with space\".into(),
                r"a\\b".into(),
            ]),
            r#"C:\Windows\System32\cmd.exe /c "echo hi there" "" "say \"x\"" "C:\dir with space\\" a\\b"#
        );
    }

    #[test]
    fn environment_blocks_are_sorted_and_double_terminated() {
        let env = BTreeMap::from([
            ("b".to_string(), "2".to_string()),
            ("A".to_string(), "1".to_string()),
        ]);
        assert_eq!(
            String::from_utf16(&environment_block(&env)).unwrap(),
            "A=1\0b=2\0\0"
        );
        assert_eq!(environment_block(&BTreeMap::new()), vec![0, 0]);
    }
}
