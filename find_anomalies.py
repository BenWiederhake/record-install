#!/usr/bin/env python3

import json
import sys


# FIXME: This set should be empty.
UNCHECKED_SYSCALLS = {
    "access",
    "arch_prctl",
    "bind",
    "brk",
    "chmod",
    "clock_nanosleep",
    "clone",
    "clone3",
    "connect",
    "epoll_create1",
    "execve",
    "fadvise64",
    "fcntl",
    "fsync",
    "futex",
    "getcwd",
    "getdents64",
    "getegid",
    "geteuid",
    "getgid",
    "getpeername",
    "getpid",
    "getppid",
    "getrandom",
    "getsockname",
    "getsockopt",
    "gettid",
    "getuid",
    "ioctl",
    "lseek",
    "madvise",
    "mkdir",
    "mmap",
    "mprotect",
    "mremap",
    "munmap",
    "newfstatat",
    "open",
    "openat",
    "pipe2",
    "poll",
    "pread64",
    "prlimit64",
    "read",
    "readlink",
    "recvfrom",
    "recvmsg",
    "rename",
    "rmdir",
    "rseq",
    "rt_sigaction",
    "rt_sigprocmask",
    "rt_sigreturn",
    "sched_getaffinity",
    "sendmmsg",
    "sendto",
    "set_robust_list",
    "setsockopt",
    "set_tid_address",
    "sigaltstack",
    "socket",
    "statx",
    "sysinfo",
    "umask",
    "uname",
    "unlink",
    "unlinkat",
    "vfork",
    "wait4",
    "write",
}
IGNORE_SYSCALLS = UNCHECKED_SYSCALLS | {
    "close",
    "close_range",
    "dup",
    "dup2",
}
IGNORE_EXITS = {0}
IGNORE_SIGNALS = {"SIGCHLD"}

SYSCALL_CHECKS = dict()


def syscall_check(fn):
    global SYSCALL_CHECKS
    name = fn.__name__
    prefix = "check_"
    assert name.startswith(prefix), name
    command_name = name[len(prefix) :]
    assert command_name not in SYSCALL_CHECKS
    SYSCALL_CHECKS[command_name] = fn
    return fn


class PidEventScanner:
    def __init__(self, pid, out_anomalous_events):
        self.pid = pid
        self.anomalous_events = out_anomalous_events

    def swallow_event(self, event):
        if event["type"] == "syscall" and self.is_syscall_okay(event):
            return
        if event["type"] == "signal" and event["signal_name"] in IGNORE_SIGNALS:
            return
        if event["type"] == "exit" and event["returncode"] in IGNORE_EXITS:
            return
        assert "pid" not in event
        event["pid"] = self.pid
        self.anomalous_events.append(event)

    def is_syscall_okay(self, syscall_event):
        if syscall_event["syscall_name"] in IGNORE_SYSCALLS:
            return True
        is_okay_fn = SYSCALL_CHECKS.get(syscall_event["syscall_name"], None)
        if is_okay_fn is not None:
            return is_okay_fn(self, syscall_event)
        # FIXME: Implement more syscalls, and/or update state
        return False

    @syscall_check
    def check_exit_group(self, syscall_event):
        args = syscall_event["args"]
        return len(args) == 1 and args[0]["type"] == "int_b10" and args[0]["value"] == 0

    @syscall_check
    def check_exit(self, syscall_event):
        args = syscall_event["args"]
        return len(args) == 1 and args[0]["type"] == "int_b10" and args[0]["value"] == 0


def run_on(events_data):
    anomalous_events = []
    for pid, pid_events in events_data["events"].items():
        scanner = PidEventScanner(pid, anomalous_events)
        for event in pid_events:
            scanner.swallow_event(event)
    return anomalous_events


def run(events_json_filename):
    with open(events_json_filename, "r") as fp:
        events = json.load(fp)
    anomalous_events = run_on(events)
    # TODO: Do something clever with the result
    for event in anomalous_events:
        print(json.dumps(event))
    print(f"Found {len(anomalous_events)} anomalous events; parsing had {len(events['parse_errors'])} errors.")
    something_weird = bool(anomalous_events)
    something_weird |= bool(events['parse_errors'])
    return int(something_weird)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"USAGE: {sys.argv[0]} /path/to/events.json", file=sys.stderr)
        exit(1)
    exit(run(sys.argv[1]))
