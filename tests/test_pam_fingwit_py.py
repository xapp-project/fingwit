#!/usr/bin/python3
"""
Unit tests for the decision logic in pam_fingwit.py.

The helper is loaded under a name other than __main__ so its CLI block stays
out of the way, then individual pieces are replaced to drive it down paths
that are awkward to reach from outside.
"""
import importlib.util
import os
import sys

# The helper is loaded from the source tree; don't leave a __pycache__ there.
sys.dont_write_bytecode = True

import PAM

HELPER = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "pam_fingwit.py")

passed = 0
failed = 0


def load_helper():
    spec = importlib.util.spec_from_file_location("pam_fingwit_helper", HELPER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Handle:
    def __init__(self, user="testuser"):
        self._user = user

    def get_user(self):
        return self._user


def raises(*args, **kwargs):
    raise RuntimeError("induced failure")


class BrokenGio:
    """Stands in for gi.repository.Gio when even the settings lookup fails."""
    Settings = staticmethod(raises)


def check(name, expected, module, user="testuser"):
    global passed, failed
    try:
        got = module.pam_sm_authenticate(Handle(user), 0, [])
    except Exception as error:
        print("  \033[31mFAIL\033[0m %s\n       raised %s: %s"
              % (name, type(error).__name__, error))
        failed += 1
        return
    if got == expected:
        print("  \033[32mPASS\033[0m %s" % name)
        passed += 1
    else:
        print("  \033[31mFAIL\033[0m %s\n       got %s, expected %s"
              % (name, got, expected))
        failed += 1


print("== helper decision logic ==")

# The settings lookup is the first thing the helper does, before it has parsed
# its own arguments. An error there must still be handled.
module = load_helper()
module.Gio = BrokenGio
check("a failure before the debug flag is parsed is handled",
      PAM.PAM_AUTHINFO_UNAVAIL, module)

# Any other internal error has to skip fprintd. Letting it run is how
# fingerprint authentication ends up offered at initial login, where the
# keyring and an encrypted home still need the password.
module = load_helper()
module.is_ssh_session = raises
check("an internal error skips fprintd rather than allowing it",
      PAM.PAM_AUTHINFO_UNAVAIL, module)

# No username means no decision either.
module = load_helper()
module.is_ssh_session = lambda: False
check("an empty username skips fprintd rather than allowing it",
      PAM.PAM_AUTHINFO_UNAVAIL, module, user="")

# The two normal outcomes must be unaffected.
module = load_helper()
module.is_ssh_session = lambda: True
check("an SSH session skips fprintd", PAM.PAM_AUTHINFO_UNAVAIL, module)

module = load_helper()
module.is_ssh_session = lambda: False
module.user_has_session = lambda user: True
check("an existing seated session lets fprintd run", PAM.PAM_IGNORE, module)

print()
print("%d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
