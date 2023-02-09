# record-install

Record the installation of a Python package, and report any anomalies found,
for example reading ssh private keys, or https connections with unrecognized
hosts.

This project is merely a Proof of Concept. The goal is:
- Raise as few as possible false negatives. Ideally, `pip install django` would find zero anomalies, for example.
- Report any anomalous behavior, including but not limited to:
  * anomalous exit codes (packages from PyPI don't usually cause non-zero exit codes anywhere)
  * anomalous syscalls, e.g. setuid, capget/capset, fchmod, prctl, memfd_create (installing a package should only write some files to disk, not do anything fancy)
  * anomalous file access, e.g. reading private ssh keys, persist an executable in unexpected locations (installation should only depend on very little config; and should be entirely contained in the virtualenv, if existing)
  * anomalous network traffic, e.g. raw ICMP, suspicious DNS requests, unrecognized hosts (packages should never "phone home", and installation should only access the PyPI servers)

There are also some "malicious do not install" packages:
- [malicious-donotinstall-httpspost](https://pypi.org/project/malicious-donotinstall-httpspost/), which makes an HTTPS connection to a non-PyPI host during module import.
- (more packages to follow)

This serves both as a "known positive" to check against, as well as a demonstration that PyPI currently does not check for these things.

I am absolutely aware that a software repository cannot be 100% free of suspicious behavior. But it seems to me that checks like these could significantly raise the bar. That's why I wrote these PoCs.

## Table of Contents

- [Install](#install)
- [Usage](#usage)
- [Notes](#notes)
- [TODOs](#todos)
- [NOTDOs](#notdos)
- [Contribute](#contribute)

## Install

This is a Proof of Concept, so this should not be installed.

However, there are some prerequisites you might want to install:

```
$ # Install pip, python, sh, and strace using your OS's package manager
$ pip install lark
```

## Usage

Example run:

```
$ ./record_installation.sh django
Using .venv_tmp_SlNWRo7V to install package 'django', logging to install_1675972694_zQTcL4qG.log
Setting up venv ...
Running and recording ...
Done. Recorded roughly 89600 syscalls in install_1675972694_zQTcL4qG.log

$ ./transform_log.py install_1675972694_zQTcL4qG.log events_django.json
Finished parsing 89175 events across 21 processes, with 0 errors.

$ ./find_anomalies.py events_django.json 
Found 0 anomalous events; parsing had 0 errors.
```

In detail:
- `record_installation.sh` (which uses `install_and_import.sh`) sets up a temporary virtualenv, and straces both the installation, as well as very light-weight use of the module. The idea is that `install_and_import.sh` can later be moved to a VM, where any damage of a truly malicious package would be contained.
- `./transform_log.py` (which imports `parse_arg.py`, which is tested by `tests.py`) just parses the strace output into machine-readable JSON. I which strace just had a `--format=json` flag.
- `./find_anomalies.py` looks at the machine-readable JSON and reports any and all suspicious behavior.
- `malicious_donotinstall_httpspost/` is an example module that makes a suspicious HTTPS POST request upon being loaded. This simulates data exfiltration, or "phoning home" in general.

## Notes

- The strace part was written with very specific goals in mind.
  The code to be straced is potentially malicious, and might do something that kills strace at any moment,
  or might even take over the strace process. Therefore, we want to eventually run strace and the tracee on a guest VM, for containment.
  Furthermore, we want the output of strace piped directly to a file on the host, in such a way that previous output cannot be
  truncated/overwritten, and that the unfinished syscall that killed strace is still visible.
  As a working example, I tested this wil `killall -9 strace`, and the current setup seems to work.
  Note that many of the "obvious" approach fail, for example writing to many separate files, which a malicious package could in theory overwrite/replace.
- I am very surprised that parsing the output of strace is highly nontrivial.
- At the moment, `find_anomalies` is extremely rudimentary, and will mix and match blocklist/allowlist thinking where appropriate.
  The long-term idea is to *only* apply very careful allowlist-thinking. The idea is that *any* suspicious behavior should raise a flag,
  including an unknown syscall, parse errors, or reading unusual files.

## TODOs

* Make `find_anomalies.py` detect my "malicious" package as malicious.
* Write some more "malicious" packages.
* Maybe perhaps try to find an actually-malicious package?
* Maybe perhaps integrate this tool into the PyPI infrastructure?

## NOTDOs

Here are some things this project will definitely not do:
* Try to "prove" that any given package is "safe", by any definition. (See also: [Rice's theorem](https://en.wikipedia.org/wiki/Rice's_theorem))
* Try to "detect all malicious behavior"; see previous bullet.
* Any kind of static analysis.
* Try to inspect network traffic. We already flag all non-DNS, non-PyPI traffic, so this seems unnecessary.
* Try to "prevent" any malicious behavior. Analyzing a static strace log is much simpler than doing any real-time interactions with a possibly-compromised host.
* Reimplement in Rust. This is a Proof of Concept, and the performance already is reasonably okay (the parser can do about 8k events per second, the finder should be even quicker).

## Contribute

Feel free to dive in! [Open an issue](https://github.com/BenWiederhake/record-install/issues/new) or submit PRs.
