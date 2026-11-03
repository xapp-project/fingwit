/*
 * pam_fingwit - Smart fingerprint PAM module
 * C wrapper for Python implementation
 */

#define _GNU_SOURCE
#include <security/pam_modules.h>
#include <security/pam_appl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>

#define PYTHON_SCRIPT PYTHON_SCRIPT_DIR "/pam_fingwit.py"

#ifndef PYTHON_BIN
#define PYTHON_BIN "/usr/bin/python3"
#endif

static const char *const ssh_markers[] = {
    "SSH_CLIENT", "SSH_CONNECTION", "SSH_TTY", "SSH_ORIGINAL_COMMAND", NULL
};

/* Only an explicit PAM_IGNORE from the helper means "go ahead and try the
 * fingerprint". Anything else (error, crash, signal, missing dependency)
 * returns PAM_AUTHINFO_UNAVAIL so that the fingerprint step is skipped and
 * the password is required. */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *user;
    const char *service = NULL;
    const char *value;
    char *envp[8];
    char **args;
    int ret, i, n, status;
    pid_t pid;

    ret = pam_get_user(pamh, &user, NULL);
    if (ret != PAM_SUCCESS || user == NULL) return PAM_AUTHINFO_UNAVAIL;

    if (pam_get_item(pamh, PAM_SERVICE, (const void **)&service) != PAM_SUCCESS || service == NULL)
        service = "unknown";

    // python3 -I script --pam user service arg1 arg2 ...
    args = calloc(argc + 8, sizeof(char *));
    if (!args) return PAM_AUTHINFO_UNAVAIL;

    n = 0;
    args[n++] = (char *)"python3";
    args[n++] = (char *)"-I";
    args[n++] = (char *)PYTHON_SCRIPT;
    args[n++] = (char *)"--pam";
    args[n++] = (char *)user;
    args[n++] = (char *)service;
    for (i = 0; i < argc; i++)
        args[n++] = (char *)argv[i];
    args[n] = NULL;

    // The caller (sudo, su, polkit-agent-helper-1...) is setuid root and has
    // not yet sanitized its environment, so never hand it to the helper.
    // Build a fresh one instead.
    memset(envp, 0, sizeof(envp));
    n = 0;
    for (i = 0; ssh_markers[i] != NULL; i++) {
        value = getenv(ssh_markers[i]);
        if (value == NULL || *value == '\0')
            continue;
        if (asprintf(&envp[n++], "%s=%s", ssh_markers[i], value) < 0) {
            envp[n - 1] = NULL;
            goto unavail;
        }
    }
    if (asprintf(&envp[n++], "PAM_USER=%s", user) < 0) {
        envp[n - 1] = NULL;
        goto unavail;
    }
    if (asprintf(&envp[n++], "PAM_SERVICE=%s", service) < 0) {
        envp[n - 1] = NULL;
        goto unavail;
    }
    envp[n++] = (char *)"PATH=/usr/sbin:/usr/bin:/sbin:/bin";
    envp[n] = NULL;

    pid = fork();
    if (pid == 0) {
        // Detach the inherited descriptors from PAM. In the polkit
        // agent helper these are the protocol socket back to the
        // authentication agent; any stray output from python (or glib)
        // would corrupt that stream.
        int devnull = open("/dev/null", O_RDWR);
        if (devnull >= 0) {
            dup2(devnull, STDIN_FILENO);
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            if (devnull > STDERR_FILENO)
                close(devnull);
        }

        execve(PYTHON_BIN, args, envp);
        _exit(PAM_AUTHINFO_UNAVAIL);
    }

    if (pid < 0)
        goto unavail;

    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) {
            ret = PAM_AUTHINFO_UNAVAIL;
            goto done;
        }
    }
    ret = (WIFEXITED(status) && WEXITSTATUS(status) == PAM_IGNORE) ? PAM_IGNORE : PAM_AUTHINFO_UNAVAIL;
    goto done;

unavail:
    ret = PAM_AUTHINFO_UNAVAIL;
done:
    // everything but the trailing PATH entry was allocated by asprintf
    for (i = 0; envp[i] != NULL && strncmp(envp[i], "PATH=", 5) != 0; i++)
        free(envp[i]);
    free(args);
    return ret;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_IGNORE;
}