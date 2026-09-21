#!/bin/bash
#
# Builds and stages the project into a throwaway prefix, then runs the test
# suite against that installed tree. Staging matters: the module compiles the
# helper's path in at build time, so the tests have to exercise the same
# layout the package ships.
#
# A second, instrumented build replaces the interpreter with a script that
# dumps its environment, which is how the environment allowlist is checked.
#
# usage: tests/run.sh [builddir]
set -eu

here=$(cd "$(dirname "$0")" && pwd)
source_dir=$(dirname "$here")
build=${1:-$source_dir/builddir-tests}
prefix=$build/prefix
dump_path=$build/envdump

rm -rf "$build"
mkdir -p "$build"

meson setup "$build/module" "$source_dir" --prefix="$prefix" >/dev/null
meson setup "$build/envdump-module" "$source_dir" --prefix="$prefix" \
    -Dpython_executable="$dump_path" >/dev/null
meson install -C "$build/module" >/dev/null
meson compile -C "$build/envdump-module" pam_fingwit >/dev/null

cc -Wall -Wextra -o "$build/pam_driver" "$here/pam_driver.c" -lpam -ldl

status=0

FINGWIT_ENVDUMP_SO="$build/envdump-module/pam_fingwit.so" \
FINGWIT_ENVDUMP_PATH="$dump_path" \
    "$here/test_pam_fingwit.sh" "$build/module/pam_fingwit.so" "$build/pam_driver" || status=1

echo
/usr/bin/python3 "$here/test_pam_fingwit_py.py" || status=1

exit $status
