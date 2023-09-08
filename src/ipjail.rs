use anyhow::*;

const IPTABLES: &str = "/sbin/iptables";
const IP6TABLES: &str = "/sbin/ip6tables";
const GROUP: &str = "no-internet";

macro_rules! run {
    ($program:expr $(, $arg:expr)* $(,)?) => { unsafe {
        let mut pipe = [0; 2];
        libc::pipe(&mut pipe[0]);
        let child = libc::fork();
        if child == 0 {
            libc::close(pipe[0]);
            libc::setsid();
            libc::setuid(0);
            libc::dup2(pipe[1], libc::STDOUT_FILENO);
            let program = std::ffi::CString::new($program).unwrap();
            let args = vec![$(std::ffi::CString::new($arg).unwrap()),*];
            let arg_ptrs = std::iter::once(program.as_ptr())
                .chain(args.iter().map(|x| x.as_ptr()))
                .chain(std::iter::once(std::ptr::null()))
                .collect::<Vec<_>>();
            libc::execv(program.as_ptr(), arg_ptrs.as_ptr());
            bail!("failed to run command");
        } else {
            libc::close(pipe[1]);
            let mut status = 0;
            libc::waitpid(child, &mut status, 0);
            ensure!(status == 0, "command {} failed", $program);
            let mut res = Default::default();
            let mut f: std::fs::File = std::os::fd::FromRawFd::from_raw_fd(pipe[0]);
            std::io::Read::read_to_string(&mut f, &mut res)?;
            res
        }
    }}
}

fn main() -> Result<()> {
    let real = unsafe { libc::getuid() };
    let effective = unsafe { libc::geteuid() };

    ensure!(effective == 0, "this program must be run with SUID");

    let mut args = std::env::args().skip(1);
    let program = args.next().context("no program provided in argument")?;

    if !run!(IPTABLES, "-L").contains("no-internet") {
        run!(
            IPTABLES,
            "-I",
            "OUTPUT",
            "1",
            "-m",
            "owner",
            "--gid-owner",
            GROUP,
            "-j",
            "DROP",
        );
        eprintln!("Initialized IPv4 rule");
    }

    if !run!(IP6TABLES, "-L").contains("no-internet") {
        run!(
            IP6TABLES,
            "-I",
            "OUTPUT",
            "1",
            "-m",
            "owner",
            "--gid-owner",
            GROUP,
            "-j",
            "DROP",
        );
        eprintln!("Initialized IPv6 rule");
    }

    unsafe {
        let cstr = std::ffi::CString::new(GROUP).unwrap();
        let group = libc::getgrnam(cstr.as_ptr());
        ensure!(!group.is_null(), "no group {:?}", GROUP);
        let gid = (*group).gr_gid;
        let group_len = libc::getgroups(0, std::ptr::null_mut()) + 1;
        let mut groups = vec![0; group_len as _];
        libc::getgroups(group_len, &mut groups[1]);
        let group_len = group_len as usize;
        groups[0] = gid;
        libc::setgroups(group_len, &groups[0]);
        libc::setgid(gid);
    }

    unsafe { libc::setuid(real) };

    unsafe {
        let program = std::ffi::CString::new(program).unwrap();
        let args = args
            .map(|x| std::ffi::CString::new(x).unwrap())
            .collect::<Vec<_>>();
        let arg_ptrs = std::iter::once(program.as_ptr())
            .chain(args.iter().map(|x| x.as_ptr()))
            .chain(std::iter::once(std::ptr::null()))
            .collect::<Vec<_>>();
        libc::execvp(program.as_ptr(), arg_ptrs.as_ptr());
        bail!("failed to run command");
    }
}
