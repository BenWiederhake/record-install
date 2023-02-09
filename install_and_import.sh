#!/bin/sh
set -eu

if [ "$#" != "2" ]; then
    echo "USAGE: $0 VENVDIR PACKAGE_NAME"
    exit 1
fi

PYTHON="${PYTHON:-python3}"
PIP="${PIP:-pip3}"
VENVDIR="$1"
PACKAGE="$2"

# exec 42>&2
# echo "foobar" >&42

# Make sure we don't confuse the parser
exec >/dev/null
exec 2>/dev/null

echo "Activating venv ..."
. "$VENVDIR/bin/activate"

"$PIP" install --upgrade "$PACKAGE"

"$PYTHON" -c "\
import $PACKAGE
print($PACKAGE.__dict__)  # Potentially trigger some payloads
import time
time.sleep(0.1)  # Potentially trigger some payloads
"
