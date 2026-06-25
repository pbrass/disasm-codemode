#!/usr/bin/env bash
# Open a file as a TAB in the running Binary Ninja code-mode MCP instance (not a new window),
# and let analysis run, so the bn-inspect/bn-hunt/bulk-decompile tools can use --bv-match
# against it. Equivalent to phil_notes/bnopen.sh, but resolves binja.py relative to itself
# (portable when installed as a plugin) instead of a hardcoded path.
# Usage: bnopen.sh /path/to/binary
here="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
target="$1"
[ -n "$target" ] || { echo "usage: bnopen.sh /path/to/binary" >&2; exit 2; }
# the path is interpolated into the executed Python below + a shell-quoted string; refuse any
# character that could break out (quotes, $, backtick, ;, space, control) -> command injection.
if printf '%s' "$target" | LC_ALL=C grep -q '[^A-Za-z0-9_./+=-]'; then
  echo "bnopen.sh: path has characters outside [A-Za-z0-9_./+=-]; refusing" >&2; exit 2
fi
# Absolutize relative to the CALLER's cwd: Binary Ninja's process cwd may be a plugin dir
# (e.g. a web-server plugin), so a relative path would resolve there and fail to open.
target="$(realpath -m -- "$target")"
exec python3 "$here/binja.py" "
import binaryninja
from binaryninjaui import UIContext
def do_open(p='$target'):
    from binaryninjaui import UIContext as U
    U.allContexts()[0].openFilename(p)
binaryninja.execute_on_main_thread_and_wait(do_open)
print('opened tab for: $target')
"
