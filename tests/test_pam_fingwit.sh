#!/bin/bash
#
# Regression and hardening tests for pam_fingwit.so.
#
# Runs unprivileged and touches nothing outside a temporary directory. The
# module is loaded through tests/pam_driver.c, which prints its return code.
#
# usage: test_pam_fingwit.sh <pam_fingwit.so> <pam_driver>
#
# Optional: to also check the environment allowlist, set FINGWIT_ENVDUMP_PATH to
# an absolute path and FINGWIT_ENVDUMP_SO to a pam_fingwit.so built with
# -Dpython_executable=$FINGWIT_ENVDUMP_PATH. tests/run.sh wires this up.

set -u

MODULE=${1:?usage: $0 <pam_fingwit.so> <pam_driver>}
DRIVER=${2:?usage: $0 <pam_fingwit.so> <pam_driver>}

PAM_IGNORE=25
PAM_AUTHINFO_UNAVAIL=9

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

pass=0
fail=0

ok()   { printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass + 1)); }
ko()   { printf '  \033[31mFAIL\033[0m %s\n' "$1"; [ $# -gt 1 ] && printf '       %s\n' "$2"; fail=$((fail + 1)); }

# Run the module. Args: <service> [env assignments...]
run_module() {
    local service=$1; shift
    env "$@" "$DRIVER" "$MODULE" "$service" "$USER" debug 2>"$WORK/stderr"
}

echo "== decision regression =="

# The module must keep returning PAM_IGNORE for a user who already has a
# seated session: that is what lets pam_fprintd.so run for sudo/polkit.
got=$(run_module sudo)
if [ "$got" = "$PAM_IGNORE" ]; then
    ok "sudo in a desktop session returns PAM_IGNORE ($PAM_IGNORE)"
else
    ko "sudo in a desktop session returns PAM_IGNORE ($PAM_IGNORE)" "got '$got'"
fi

# SSH must always skip fprintd.
got=$(run_module sudo SSH_CLIENT="10.0.0.1 1234 22")
if [ "$got" = "$PAM_AUTHINFO_UNAVAIL" ]; then
    ok "sudo over SSH returns PAM_AUTHINFO_UNAVAIL ($PAM_AUTHINFO_UNAVAIL)"
else
    ko "sudo over SSH returns PAM_AUTHINFO_UNAVAIL ($PAM_AUTHINFO_UNAVAIL)" "got '$got'"
fi

got=$(run_module sudo SSH_CONNECTION="10.0.0.1 1234 10.0.0.2 22")
if [ "$got" = "$PAM_AUTHINFO_UNAVAIL" ]; then
    ok "SSH_CONNECTION alone is enough to skip fprintd"
else
    ko "SSH_CONNECTION alone is enough to skip fprintd" "got '$got'"
fi

# The module must never leak output onto the caller's stdio: in the polkit
# agent those descriptors carry the helper protocol.
got=$(run_module sudo)
if [ ! -s "$WORK/stderr" ]; then
    ok "module writes nothing to stderr"
else
    ko "module writes nothing to stderr" "got: $(head -c 200 "$WORK/stderr")"
fi

echo "== hardening: interpreter resolution (issues #54, #51) =="

# A python3 earlier in PATH must never be executed: under sudo or pkexec the
# forked child still has euid 0, so that is a root code execution primitive.
mkdir -p "$WORK/evil"
cat > "$WORK/evil/python3" <<EOF
#!/bin/sh
: > "$WORK/hijacked"
exit $PAM_IGNORE
EOF
chmod +x "$WORK/evil/python3"

rm -f "$WORK/hijacked"
got=$(run_module sudo PATH="$WORK/evil:$PATH")
if [ ! -e "$WORK/hijacked" ]; then
    ok "a python3 planted in PATH is not executed"
else
    ko "a python3 planted in PATH is not executed" "the planted interpreter ran (return code '$got')"
fi

# The decision must also still be correct with a hostile PATH, which proves the
# module found the real interpreter by absolute path rather than by luck.
if [ "$got" = "$PAM_IGNORE" ]; then
    ok "decision is still correct with a hijacked PATH"
else
    ko "decision is still correct with a hijacked PATH" "got '$got'"
fi

# An empty PATH must not break the module at all.
rm -f "$WORK/hijacked"
got=$(run_module sudo PATH=)
if [ "$got" = "$PAM_IGNORE" ]; then
    ok "decision is still correct with an empty PATH"
else
    ko "decision is still correct with an empty PATH" "got '$got'"
fi

echo "== hardening: environment sanitising (issue #54) =="

# PYTHONPATH is a code execution primitive for the same reason PATH is: the
# script imports gi, json and PAM before it does anything else.
mkdir -p "$WORK/pp"
cat > "$WORK/pp/sitecustomize.py" <<EOF
open("$WORK/pythonpath-honoured", "w").close()
EOF

rm -f "$WORK/pythonpath-honoured"
got=$(run_module sudo PYTHONPATH="$WORK/pp")
if [ ! -e "$WORK/pythonpath-honoured" ]; then
    ok "PYTHONPATH from the caller is not passed to the interpreter"
else
    ko "PYTHONPATH from the caller is not passed to the interpreter" "the planted sitecustomize.py was imported"
fi

if [ -n "${FINGWIT_ENVDUMP_SO:-}" ] && [ -n "${FINGWIT_ENVDUMP_PATH:-}" ]; then
    # This build of the module execs $FINGWIT_ENVDUMP_PATH instead of the real
    # interpreter, so the child's environment can be read back verbatim.
    dump_out="$FINGWIT_ENVDUMP_PATH.env"
    cat > "$FINGWIT_ENVDUMP_PATH" <<EOF
#!/bin/sh
env > "$dump_out"
exit $PAM_IGNORE
EOF
    chmod +x "$FINGWIT_ENVDUMP_PATH"

    rm -f "$dump_out"
    env PATH="$WORK/evil:$PATH" \
        PYTHONPATH="$WORK/pp" \
        PYTHONHOME=/tmp/evil \
        LD_PRELOAD=/tmp/evil/libevil.so \
        LD_LIBRARY_PATH=/tmp/evil \
        GIO_EXTRA_MODULES=/tmp/evil \
        GSETTINGS_SCHEMA_DIR=/tmp/evil \
        XDG_DATA_DIRS=/tmp/evil \
        BASH_ENV=/tmp/evil/rc \
        SSH_CLIENT="10.0.0.1 1234 22" \
        "$DRIVER" "$FINGWIT_ENVDUMP_SO" sudo "$USER" debug >/dev/null 2>&1

    if [ ! -f "$dump_out" ]; then
        ko "environment allowlist" "the env-dump build did not run; check -Dpython_executable"
    else
        for var in PYTHONPATH PYTHONHOME LD_PRELOAD LD_LIBRARY_PATH \
                   GIO_EXTRA_MODULES GSETTINGS_SCHEMA_DIR XDG_DATA_DIRS BASH_ENV; do
            if ! grep -q "^$var=" "$dump_out"; then
                ok "$var is stripped from the child environment"
            else
                ko "$var is stripped from the child environment" "$(grep "^$var=" "$dump_out")"
            fi
        done

        # SSH detection reads this, so it has to survive.
        if grep -q '^SSH_CLIENT=10.0.0.1 1234 22$' "$dump_out"; then
            ok "SSH_CLIENT is forwarded so SSH sessions are still detected"
        else
            ko "SSH_CLIENT is forwarded so SSH sessions are still detected" "not found in child environment"
        fi

        if grep -q "^PATH=" "$dump_out" && ! grep -q "^PATH=.*evil" "$dump_out"; then
            ok "PATH is replaced with a fixed safe value"
        else
            ko "PATH is replaced with a fixed safe value" "$(grep '^PATH=' "$dump_out")"
        fi

        if grep -q "^PAM_SERVICE=sudo$" "$dump_out"; then
            ok "PAM_SERVICE is set from the PAM item"
        else
            ko "PAM_SERVICE is set from the PAM item" "$(grep '^PAM_SERVICE=' "$dump_out")"
        fi
    fi
    echo "== hardening: child and wait handling =="

    # PAM is full of signals (SIGCHLD, SIGALRM, SIGWINCH). If waitpid() is
    # interrupted the module must wait again, not read an uninitialised status
    # and decide authentication from whatever was on the stack.
    marker="$FINGWIT_ENVDUMP_PATH.finished"
    cat > "$FINGWIT_ENVDUMP_PATH" <<EOF
#!/bin/sh
sleep 1
: > "$marker"
exit $PAM_IGNORE
EOF
    chmod +x "$FINGWIT_ENVDUMP_PATH"

    rm -f "$marker"
    got=$(FINGWIT_DRIVER_ALARM_MS=200 "$DRIVER" "$FINGWIT_ENVDUMP_SO" sudo "$USER" debug 2>/dev/null)
    if [ -e "$marker" ]; then
        ok "a signal during the wait does not cut the helper short"
    else
        ko "a signal during the wait does not cut the helper short" "module returned '$got' while the helper was still running"
    fi
    if [ "$got" = "$PAM_IGNORE" ]; then
        ok "the helper's exit code is still read after a signal"
    else
        ko "the helper's exit code is still read after a signal" "got '$got'"
    fi

    # If exec fails, the child must leave with _exit(): exit() would flush the
    # stdio buffers it inherited from the process that loaded the module.
    rm -f "$FINGWIT_ENVDUMP_PATH"
    log="$WORK/buffered.log"
    FINGWIT_DRIVER_BUFFERED_LOG="$log" "$DRIVER" "$FINGWIT_ENVDUMP_SO" sudo "$USER" debug >/dev/null 2>&1
    count=$(grep -c '^marker$' "$log" 2>/dev/null || echo 0)
    if [ "$count" = "1" ]; then
        ok "a failed exec does not flush the caller's stdio buffers"
    else
        ko "a failed exec does not flush the caller's stdio buffers" "marker written $count times, expected 1"
    fi
else
    echo "  SKIP environment allowlist (set FINGWIT_ENVDUMP_SO and FINGWIT_ENVDUMP_PATH)"
fi

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
