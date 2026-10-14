//! Process hardening applied at startup (7.11 F8): a crash must not write a core dump holding
//! profile keys or plaintext to disk. Every binary entry point must call
//! [`disable_core_dumps`] first.

use std::io;

/// Disable core dumps for this process: `RLIMIT_CORE = 0` (hard and soft, so an unprivileged
/// process cannot raise it again; root/`CAP_SYS_RESOURCE` can) and, on Linux,
/// `PR_SET_DUMPABLE = 0`. The latter is the real defence when `core_pattern` is a pipe (the
/// kernel then ignores `RLIMIT_CORE`); it also blocks same-uid ptrace. Dumpable resets on
/// `execve`, so re-check before ever spawning a subprocess.
pub fn disable_core_dumps() -> io::Result<()> {
    let zero = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `zero` is a valid, initialised rlimit that outlives the call.
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &zero) } != 0 {
        return Err(io::Error::last_os_error());
    }
    #[cfg(target_os = "linux")]
    {
        let z: libc::c_ulong = 0;
        // SAFETY: prctl(2) reads its variadic arguments as `unsigned long`, passed as such.
        if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, z, z, z, z) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_limit_is_zero_after_call() {
        disable_core_dumps().unwrap();
        let mut got = libc::rlimit {
            rlim_cur: 1,
            rlim_max: 1,
        };
        // SAFETY: `got` is a valid out-pointer.
        assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut got) }, 0);
        assert_eq!((got.rlim_cur, got.rlim_max), (0, 0));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn process_is_not_dumpable_after_call() {
        disable_core_dumps().unwrap();
        let z: libc::c_ulong = 0;
        // SAFETY: prctl(2) reads its variadic arguments as `unsigned long`, passed as such.
        assert_eq!(unsafe { libc::prctl(libc::PR_GET_DUMPABLE, z, z, z, z) }, 0);
    }

    #[test]
    fn limit_cannot_be_raised_unprivileged() {
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        disable_core_dumps().unwrap();
        let up = libc::rlimit {
            rlim_cur: 1,
            rlim_max: 1,
        };
        // SAFETY: `up` is a valid rlimit.
        assert_ne!(unsafe { libc::setrlimit(libc::RLIMIT_CORE, &up) }, 0);
    }

    #[test]
    fn idempotent() {
        disable_core_dumps().unwrap();
        disable_core_dumps().unwrap();
    }
}
