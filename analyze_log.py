#!/usr/bin/env python3

from collections import Counter, namedtuple
import argparse
import re

# Example:
# 19:25:45.159875 mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f3e3476b000
STRACE_LINE_RE = re.compile(r"^(?:\[pid ([0-9]+)\] )?([0-9]{2}:[0-9]{2}:[0-9]{2}.[0-9]{6}) (.+)$")

# Example:
# mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f3e3476b000
EVENT_SYSCALL_COMPLETE_RE = re.compile(r"^([a-z0-9_]{3,30})(\(.*\) += .+)$")

# Example:
# mmap(NULL, 112286, PROT_READ, MAP_PRIVATE, 3</etc/ld.so.cache>, 0 <unfinished ...>
EVENT_SYSCALL_UNFINISHED_RE = re.compile(r"^([a-z0-9_]{3,30})(\(.*) <unfinished \.\.\.>$")

# Example:
# <... newfstatat resumed>{st_mode=S_IFIFO|0600, st_size=0, ...}, AT_EMPTY_PATH) = 0
EVENT_SYSCALL_RESUME_RE = re.compile(r"^<\.\.\. ([a-z0-9_]{3,30}) resumed>(.+ = .+)$")

# Example:
# --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=3908496, si_uid=1000, si_status=0, si_utime=0, si_stime=0} ---
EVENT_SIGNAL_RE = re.compile(r"^--- (SIG[A-Z0-9]+) (\{si_[^}]+\}) ---$")

# Example:
# +++ exited with 0 +++
EVENT_EXIT_RE = re.compile(r"^\+\+\+ exited with ([0-9]+) \+\+\+$")

# Examples:
# (NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f63255bf000
# (AT_FDCWD, "/usr/lib/python3.11/encodings", O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_DIRECTORY) = 3</usr/lib/python3.11/encodings>
# (3</usr/lib/python3.11/encodings/__pycache__/aliases.cpython-311.pyc>, TCGETS, 0x7ffdc4c2b5e0) = -1 ENOTTY (Unpassender IOCTL (I/O-Control) für das Gerät)
# (3</usr/lib/python3.11/encodings/__pycache__/__init__.cpython-311.pyc>, F_GETFD) = 0x1 (flags FD_CLOEXEC)
# ([{fd=0</dev/pts/8<char 136:8>>, events=0}, {fd=1<pipe:[41666807]>, events=0}, {fd=2<pipe:[41666807]>, events=0}], 3, 0) = 0 (Timeout)
# ([{fd=3<pipe:[41666807]>, events=POLLIN}], 1, 500) = 1 ([{fd=3, revents=POLLIN}])
SYSCALL_PARSE_PARTS = re.compile(r"^\((.*)\) += (?:([0-9xa-f-]+)(?:<(.+)>)?|(\?))(?: (?:(E[A-Z]+) \(.+\)|\(flags (.+)\)|(\(Timeout\))|\(\[(\{fd=.+\})\]\)))?$")


UnfinishedSyscall = namedtuple("UnfinishedSyscall", ["name", "first_part"])


class Stats:
    def __init__(self):
        self.type_counter = Counter()
        self.parse_errors = 0
        # unfinished_syscalls is a dict of:
        # * keys: pid (e.g. -2 or 3908497)
        # * values: instance of class UnfinishedSyscall
        self.unfinished_syscalls = dict()
        self.initial_pid = None
        # Fun fact: vfork does *NOT* return twice, so no need to handle that.

    def parse_error_line(self, lineno, line):
        print(f"ERROR: Cannot parse line {lineno + 1}: Unrecognizable line '{line}'")
        self.parse_errors += 1

    def parse_error_event(self, lineno, eventstr):
        print(f"ERROR: Cannot parse line {lineno + 1}: Cannot parse event '{eventstr}'")
        self.parse_errors += 1

    def try_resolve_pid(self, pid):
        if pid == "initial" and self.initial_pid is not None:
            return self.initial_pid
        return pid

    def record_syscall_complete(self, pid, timestr, syscall_name, full_args):
        pid = self.try_resolve_pid(pid)
        self.type_counter["syscall_complete"] += 1
        if pid in self.unfinished_syscalls:
            print(f"ERROR: PID {pid} starts another unfinished syscall without returning first?! Discarding old unfinished!")
            self.parse_errors += 1
            del self.unfinished_syscalls[pid]
        self.parse_assembled_syscall(pid, timestr, syscall_name, full_args)

    def record_syscall_unfinished(self, pid, timestr, syscall_name, first_part):
        pid = self.try_resolve_pid(pid)
        self.type_counter["syscall_unfinished"] += 1
        if pid in self.unfinished_syscalls:
            print(f"ERROR: PID {pid} starts another unfinished syscall without returning first?! Discarding old unfinished!")
            self.parse_errors += 1
        self.unfinished_syscalls[pid] = UnfinishedSyscall(syscall_name, first_part)

    def record_syscall_resume(self, pid, timestr, syscall_name, last_part):
        pid = self.try_resolve_pid(pid)
        self.type_counter["syscall_resume"] += 1
        unfinished_syscall = self.unfinished_syscalls.get(pid, None)
        if unfinished_syscall is None:
            print(f"ERROR: PID {pid} returns from syscall {syscall_name} without starting one?! Discarding resume!")
            self.parse_errors += 1
            return
        del self.unfinished_syscalls[pid]
        if unfinished_syscall.name != syscall_name:
            print(f"ERROR: PID {pid} returns from syscall {syscall_name} after starting it as {unfinished_syscall.name}?! Discarding both parts!")
            self.parse_errors += 1
            # The "discard" happens implicitly by having already deleted the entry and now refusing to act upon it.
            return
        self.parse_assembled_syscall(pid, timestr, syscall_name, unfinished_syscall.first_part + last_part)

    def record_exit(self, pid, timestr, returncode):
        pid = self.try_resolve_pid(pid)
        self.type_counter["syscall_exit"] += 1
        pass  # print(f"exit -> {returncode}")

    def record_signal(self, pid, timestr, signal_name, signal_desc):
        pid = self.try_resolve_pid(pid)
        self.type_counter["syscall_signal"] += 1
        pass  # print(f"signal -> {signal_name} {signal_desc}")

    def parse_assembled_syscall(self, pid, timestr, syscall_name, full_args):
        assert pid == self.try_resolve_pid(pid)
        match = SYSCALL_PARSE_PARTS.match(full_args)
        if match is None:
            print(f"ERROR: PID {pid} {syscall_name}{full_args} cannot be parsed?!")
            self.parse_errors += 1
            return
        raw_args, retval_finished, retval_path, retval_unfinished, errno, flags, timeout, pollresult = match.groups()
        pass  # print(f"assembled_syscall [{pid}] -> {syscall_name}() -> {retval_finished=} {retval_path=} {retval_unfinished=} {errno=} {flags=} {timeout=} {pollresult=}")
        if syscall_name == "getpid" and pid == "initial":
            assert retval_finished is not None
            self.discover_initial_pid(int(retval_finished))

    def discover_initial_pid(self, numeric_pid):
        assert self.initial_pid is None
        assert "initial" not in self.unfinished_syscalls
        self.initial_pid = numeric_pid
        # TODO: Update other structures

    def print_summary(self):
        for pid, unfinished_syscall in self.unfinished_syscalls.items():
            self.parse_errors += 1
            print(f"ERROR: PID {pid} never returned from {unfinished_syscall.name}?! Discarding!")
        if self.initial_pid is None:
            self.parse_errors += 1
            print(f"ERROR: Initial pid never learned?! syscalls of initial program might be spread across two distinct entries.")
        print(f"Parsing completed with {self.parse_errors} errors. Event types: {self.type_counter.most_common()}")


PARSE_EVENT_REACTIONS = [
    (EVENT_SYSCALL_COMPLETE_RE, Stats.record_syscall_complete),
    (EVENT_SYSCALL_UNFINISHED_RE, Stats.record_syscall_unfinished),
    (EVENT_SYSCALL_RESUME_RE, Stats.record_syscall_resume),
    (EVENT_SIGNAL_RE, Stats.record_signal),
    (EVENT_EXIT_RE, Stats.record_exit),
]


def parse_pidstr(pidstr):
    if pidstr is None:
        return "initial"  # strace sometimes doesn't report the PID. Ugh!
    return int(pidstr)


def parse_line_into(line, lineno, stats):
    # Ignore the initial package name and venv-dir location:
    if lineno == 0:
        return
    # Strip down to the actual event string:
    match = STRACE_LINE_RE.match(line)
    if not match:
        stats.parse_error_line(lineno, line)
        return
    pidstr, timestr, eventstr = match.groups()
    pid = parse_pidstr(pidstr)
    # Try to recognize the event type:
    for regex, record_fn in PARSE_EVENT_REACTIONS:
        event_match = regex.match(eventstr)
        if event_match:
            record_fn(stats, pid, timestr, *event_match.groups())
            return
    # We cannot recognize this event!
    stats.parse_error_event(lineno, eventstr)


def run_with(log_filename):
    stats = Stats()
    with open(log_filename, "r") as fp:
        for lineno, line in enumerate(fp):
            line = line.strip()
            parse_line_into(line, lineno, stats)
    stats.print_summary()


def run():
    parser = argparse.ArgumentParser()
    parser.add_argument("log_filename", metavar="INSTALLATION_LOG")
    args = parser.parse_args()
    run_with(args.log_filename)


if __name__ == "__main__":
    run()
