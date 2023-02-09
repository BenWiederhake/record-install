#!/bin/sh
set -eu

if [ "$#" != "1" ]; then
    echo "USAGE: $0 PACKAGE_NAME"
    exit 1
fi

PYTHON="${PYTHON:-python3}"
PACKAGE="$1"

VENVDIR="$(mktemp -d .venv_tmp_XXXXXXXX)"
rm_venv_dir() {
    rm -rf "$VENVDIR"
}
trap rm_venv_dir EXIT

LOGFILE="$(mktemp install_"$(date +%s)"_XXXXXXXX.log)"
echo "Using $VENVDIR to install package '$PACKAGE', logging to $LOGFILE"
echo "$(date '+%H:%M:%S.000000') Using $VENVDIR to install package '$PACKAGE'." >> "$LOGFILE"
echo "Setting up venv ..."
"$PYTHON" -m venv "$VENVDIR"
echo "Running and recording ..."
strace -e all -DDD -I never_tstp -ff -tt --decode-fds=path,socket,dev,pidfd --silence=attach -s 100 \
    ./install_and_import.sh "$VENVDIR" "$PACKAGE" 2>>"$LOGFILE"
# Note that this guarantees that any malicious program creates at least *some* indicating
# that something weird happens. Use `killall -9 strace` for an example.

echo "Done. Recorded roughly $(wc -l "$LOGFILE" | cut -d" " -f1) syscalls in $LOGFILE"
