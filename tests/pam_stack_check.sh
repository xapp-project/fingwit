#!/bin/bash
#
# Exercises pam_fingwit.so through libpam's own dispatcher, to confirm the
# stack still reacts to its decisions the way fingwit.pam_config expects.
#
# This needs root, because the service file has to live in /etc/pam.d. It
# installs its own throwaway service and removes it again; no existing PAM
# configuration is read or written, and common-auth is never touched.
#
# usage: sudo tests/pam_stack_check.sh <pam_fingwit.so>
set -u

MODULE=${1:-}
if [ -z "$MODULE" ]; then
    echo "usage: sudo $0 <pam_fingwit.so>" >&2
    exit 2
fi
if [ "$(id -u)" != 0 ]; then
    echo "this check needs root: sudo $0 $MODULE" >&2
    exit 2
fi

MODULE=$(readlink -f "$MODULE")
SERVICE=fingwit-selftest
SERVICE_FILE=/etc/pam.d/$SERVICE
AS_USER=${SUDO_USER:-root}

if [ -e "$SERVICE_FILE" ]; then
    echo "refusing to run: $SERVICE_FILE already exists" >&2
    exit 2
fi

WORK=$(mktemp -d)
cleanup() { rm -f "$SERVICE_FILE"; rm -rf "$WORK"; }
trap cleanup EXIT

# The same jump the shipped configuration uses. authinfo_unavail skips the
# next module, which here is the one that fails the stack, so:
#   pam_authenticate == PAM_SUCCESS  (0) <=> the module said authinfo_unavail
#   pam_authenticate == PAM_AUTH_ERR (7) <=> the module said ignore
cat > "$SERVICE_FILE" <<CONF
auth    [authinfo_unavail=1 default=ignore]     $MODULE debug
auth    requisite                               pam_deny.so
auth    required                                pam_permit.so
CONF
chmod 644 "$SERVICE_FILE"

cc -Wall -Wextra -o "$WORK/tester" "$(dirname "$(readlink -f "$0")")/pam_stack_tester.c" -lpam || exit 2
chmod 755 "$WORK" "$WORK/tester"

SKIPPED_FPRINTD=0
RAN_FPRINTD=7

pass=0
fail=0
ok() { printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass + 1)); }
ko() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; printf '       %s\n' "$2"; fail=$((fail + 1)); }

run_as_user() { runuser -u "$AS_USER" -- env "$@" "$WORK/tester" "$SERVICE" "$AS_USER"; }

echo "== pam_fingwit.so through the real PAM stack (service: $SERVICE) =="
echo "   module: $MODULE"
echo "   caller: $AS_USER"
echo

got=$(run_as_user -i PATH=/usr/bin:/bin HOME="/home/$AS_USER" 2>/dev/null)
if [ "$got" = "$RAN_FPRINTD" ]; then
    ok "a desktop session lets the stack move on to fprintd"
else
    ko "a desktop session lets the stack move on to fprintd" "pam_authenticate returned '$got', expected $RAN_FPRINTD"
fi

got=$(run_as_user -i PATH=/usr/bin:/bin HOME="/home/$AS_USER" SSH_CLIENT="10.0.0.1 1234 22" 2>/dev/null)
if [ "$got" = "$SKIPPED_FPRINTD" ]; then
    ok "an SSH session makes the stack skip fprintd"
else
    ko "an SSH session makes the stack skip fprintd" "pam_authenticate returned '$got', expected $SKIPPED_FPRINTD"
fi

mkdir -p "$WORK/evil"
cat > "$WORK/evil/python3" <<SH
#!/bin/sh
: > "$WORK/hijacked"
exit 25
SH
chmod +x "$WORK/evil/python3"
chmod -R 755 "$WORK/evil"

rm -f "$WORK/hijacked"
got=$(run_as_user -i PATH="$WORK/evil:/usr/bin:/bin" HOME="/home/$AS_USER" 2>/dev/null)
if [ ! -e "$WORK/hijacked" ]; then
    ok "a python3 planted in PATH is not executed by the stack"
else
    ko "a python3 planted in PATH is not executed by the stack" "the planted interpreter ran"
fi
if [ "$got" = "$RAN_FPRINTD" ]; then
    ok "the decision is unchanged under a hijacked PATH"
else
    ko "the decision is unchanged under a hijacked PATH" "pam_authenticate returned '$got', expected $RAN_FPRINTD"
fi

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
