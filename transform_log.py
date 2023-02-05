#!/usr/bin/env python3

from collections import Counter, defaultdict, namedtuple
import argparse
import json
import lark
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

# Unhandled examples:
# [{fd=0</dev/pts/8<char 136:8>>, events=0}, {fd=1<pipe:[41666807]>, events=0}, {fd=2<pipe:[41666807]>, events=0}]
# {st_mode=S_IFREG|0644, st_size=112286, ...}
# ~[RTMIN RT_1]
ARG_LIST_GRAMMAR = r"""
    arg_list: (arg (", " arg)*)?
    arg: identifier -> arg_ident
        // Example: NULL
        | identifier ("|" identifier)+ -> arg_bitset
        // Example: PROT_READ|PROT_WRITE
        | int_b10 -> arg_int_b10
        // Example: 8192
        // Example: -1
        | uint_b16 -> arg_uint_b16
        // Example: 0x7ffdc4c2b5e0
        | "\"" escaped_string "\"" maybe_string_continuation -> arg_string
        // Example: "/usr/lib/python3.11/encodings"
        | uint_b10 "<" escaped_path ("<" escaped_path () ">")? ">" -> arg_path
        // Example: 3</usr/lib/python3.11/encodings/__pycache__/aliases.cpython-311.pyc>

    identifier: /[A-Z][A-Z0-9_]+/ -> token_value
    int_b10: /0|-?[1-9][0-9]*/
    uint_b10: /0|[1-9][0-9]*/ -> int_b10
    uint_b16: /0x[0-9a-f]+/
    escaped_string: escaped_string_part*
    escaped_string_part: /[^"\\]/ -> token_value
        | common_escape -> from_common_escape
    escaped_path: escaped_path_part* -> escaped_string
    escaped_path_part: /[^<>"\\]/ -> token_value
        | common_escape -> from_common_escape
    common_escape: "\\" /[tnvfr"\\]/ -> escaped_character
        | "\\" /(0|[1-7][0-7]?)(?![0-7])/ -> numeric_character
        | "\\" /[0-3][0-7][0-7]/ -> numeric_character
    maybe_string_continuation: /\.\.\./?
    """

# Although the language probably is LALR(1), the above grammar is not.
# The core of the issue seems to revolve around inputs like `1234` and `1234</tmp/foobar>`,
# and how the grammar rules represent them.
# TODO: Find a way to make the grammar LALR(1) again!
ARG_LIST_PARSER = lark.Lark(ARG_LIST_GRAMMAR, start="arg_list")

ESCAPE_CHAR_TO_CHAR = {
    "t": "\t",
    "n": "\n",
    "v": "\v",
    "f": "\f",
    "r": "\r",
    '"': '"',
    "\\": "\\",
}

inline_args = lark.v_args(inline=True)


class ArgListTransformer(lark.Transformer):
    arg_list = list

    def prefix(self, args):
        return len(args)

    @inline_args
    def arg_ident(self, identifier):
        return {"type": "identifier", "name": identifier}

    def arg_bitset(self, identifiers):
        return {"type": "bitset", "values": identifiers}

    @inline_args
    def arg_int_b10(self, value):
        return {"type": "int_b10", "value": value}

    @inline_args
    def arg_uint_b16(self, value):
        return {"type": "uint_b16", "value": value}

    @inline_args
    def token_value(self, token):
        return token.value

    @inline_args
    def int_b10(self, digits):
        return int(digits.value)

    @inline_args
    def uint_b16(self, digits):
        return int(digits.value, 16)

    def maybe_string_continuation(self, parts):
        assert parts == [] or parts == ["..."]
        if parts:
            return "incomplete"
        else:
            return "complete"

    @inline_args
    def escaped_character(self, char):
        return ESCAPE_CHAR_TO_CHAR[char.value]

    def escaped_string(self, parts):
        str_parts = []
        for i, p in enumerate(parts):
            if isinstance(p, str):
                str_parts.append(p)
            else:
                print(f"ERROR: part#{i + 1} is not a str: >>{p}<<")
        return "".join(str_parts)

    @inline_args
    def numeric_character(self, char):
        return chr(int(char.value, 8))

    @inline_args
    def from_common_escape(self, string):
        return string

    @inline_args
    def arg_string(self, string, rest):
        assert rest in ["complete", "incomplete"]
        return {
            "type": "string",
            "value": string,
            "complete": rest == "complete",
        }

    @inline_args
    def arg_path(self, fd, path, metadata=None):
        return {
            "type": "fd",
            "value": fd,
            "path": path,
            "metadata": metadata,
        }


TRANSFORMER = ArgListTransformer()

UnfinishedSyscall = namedtuple("UnfinishedSyscall", ["name", "first_part", "start_time"])


class Stats:
    def __init__(self):
        self.parse_errors = []
        # unfinished_syscalls is a dict of:
        # * keys: pid (e.g. "initial" or 3908497)
        # * values: instance of class UnfinishedSyscall
        self.unfinished_syscalls = dict()
        self.initial_pid = None
        # Fun fact: vfork does *NOT* return twice, so no need to handle that.
        # events is a dict of:
        # * keys: pid (e.g. "initial" or 3908497)
        # * values: list of events. Each event is a dict, including a field "type" which can be "syscall", "exit", or "signal".
        self.events = defaultdict(list)

    def log_error(self, errormsg):
        self.parse_errors.append(errormsg)

    def parse_error_line(self, lineno, line):
        self.log_error(f"ERROR: Cannot parse line {lineno + 1}: Unrecognizable line '{line}'")

    def parse_error_event(self, lineno, eventstr):
        self.log_error(f"ERROR: Cannot parse line {lineno + 1}: Cannot parse event '{eventstr}'")

    def try_resolve_pid(self, pid):
        if pid == "initial" and self.initial_pid is not None:
            return self.initial_pid
        return pid

    def record_syscall_complete(self, pid, timestr, syscall_name, full_args):
        pid = self.try_resolve_pid(pid)
        if pid in self.unfinished_syscalls:
            self.log_error(f"ERROR: PID {pid} starts another unfinished syscall without returning first?! Discarding old unfinished!")
            del self.unfinished_syscalls[pid]
        self.parse_assembled_syscall(pid, timestr, syscall_name, full_args, None)

    def record_syscall_unfinished(self, pid, timestr, syscall_name, first_part):
        pid = self.try_resolve_pid(pid)
        if pid in self.unfinished_syscalls:
            self.log_error(f"ERROR: PID {pid} starts another unfinished syscall without returning first?! Discarding old unfinished!")
        self.unfinished_syscalls[pid] = UnfinishedSyscall(syscall_name, first_part, timestr)

    def record_syscall_resume(self, pid, timestr, syscall_name, last_part):
        pid = self.try_resolve_pid(pid)
        unfinished_syscall = self.unfinished_syscalls.get(pid, None)
        if unfinished_syscall is None:
            self.log_error(f"ERROR: PID {pid} returns from syscall {syscall_name} without starting one?! Discarding resume!")
            return
        del self.unfinished_syscalls[pid]
        if unfinished_syscall.name != syscall_name:
            self.log_error(f"ERROR: PID {pid} returns from syscall {syscall_name} after starting it as {unfinished_syscall.name}?! Discarding both parts!")
            # The "discard" happens implicitly by having already deleted the entry and now refusing to act upon it.
            return
        self.parse_assembled_syscall(pid, timestr, syscall_name, unfinished_syscall.first_part + last_part, unfinished_syscall.start_time)

    def record_exit(self, pid, timestr, returncode):
        pid = self.try_resolve_pid(pid)
        self.events[pid].append({
            "type": "exit",
            "time": timestr,
            "returncode": returncode,
        })

    def record_signal(self, pid, timestr, signal_name, signal_desc):
        pid = self.try_resolve_pid(pid)
        self.events[pid].append({
            "type": "signal",
            "time": timestr,
            "signal_name": signal_name,
            "signal_desc": signal_desc,
        })

    def parse_assembled_syscall(self, pid, timestr, syscall_name, full_args, start_time):
        assert pid == self.try_resolve_pid(pid)
        match = SYSCALL_PARSE_PARTS.match(full_args)
        if match is None:
            self.log_error(f"ERROR: PID {pid} {syscall_name}{full_args} cannot be parsed?!")
            return
        raw_args, retval_finished, retval_path, retval_unfinished, errno, flags, timeout, pollresult = match.groups()
        args, args_parsed = self.parse_syscall_args(raw_args)
        self.events[pid].append({
            "type": "syscall",
            "time": timestr,
            "start_time": start_time,
            "syscall_name": syscall_name,
            "args": args,
            "args_parsed_successfully": args_parsed,
            "retval_finished": retval_finished,
            "retval_path": retval_path,
            "retval_unfinished": retval_unfinished,
            "errno": errno,
            "flags": flags,
            "timeout": timeout,
            "pollresult": pollresult,
        })
        if syscall_name == "getpid" and pid == "initial":
            assert retval_finished is not None
            self.discover_initial_pid(int(retval_finished))

    def parse_syscall_args(self, raw_args):
        try:
            arg_list = TRANSFORMER.transform(ARG_LIST_PARSER.parse(raw_args))
            args_parsed = True
        except (lark.exceptions.UnexpectedCharacters, lark.exceptions.UnexpectedEOF):
            arg_list = raw_args
            args_parsed = False
            self.log_error(f"ERROR: Cannot parse arglist >>({raw_args})<<")
        return arg_list, args_parsed

    def discover_initial_pid(self, numeric_pid):
        assert self.initial_pid is None
        assert "initial" not in self.unfinished_syscalls
        self.initial_pid = numeric_pid
        assert numeric_pid not in self.events, f"Fork of {numeric_pid} before getpid?! Not supported!"
        self.events[numeric_pid] = self.events["initial"]
        del self.events["initial"]

    def finish(self):
        for pid, unfinished_syscall in self.unfinished_syscalls.items():
            self.log_error(f"ERROR: PID {pid} never returned from {unfinished_syscall.name}?! Discarding!")
        if self.initial_pid is None:
            self.log_error(f"ERROR: Initial pid never learned?! syscalls of initial program might be spread across two distinct entries.")
        else:
            assert "initial" not in self.events
        return {
            "initial_pid": self.initial_pid,
            "parse_errors": self.parse_errors,
            "events": self.events,
        }


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


def run_with(log_filename, json_filename):
    stats = Stats()
    with open(log_filename, "r") as fp:
        for lineno, line in enumerate(fp):
            line = line.strip()
            parse_line_into(line, lineno, stats)
    stats_dict = stats.finish()
    with open(json_filename, "w") as fp:
        json.dump(stats_dict, fp)
    for error in stats_dict['parse_errors']:
        print(error)
    print(f"Finished parsing {sum(len(entries) for entries in stats_dict['events'].values())} events across {len(stats_dict['events'])} processes.")


def run():
    parser = argparse.ArgumentParser()
    parser.add_argument("log_filename", metavar="INSTALLATION_LOG")
    parser.add_argument("json_filename", metavar="JSON_OUTPUT")
    args = parser.parse_args()
    run_with(args.log_filename, args.json_filename)


if __name__ == "__main__":
    run()
