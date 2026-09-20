/*
 * pam_fingwit - Smart fingerprint PAM module
 * C wrapper for Python implementation
 */

#include <security/pam_modules.h>
#include <security/pam_appl.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>

#define PYTHON_SCRIPT PYTHON_SCRIPT_DIR "/pam_fingwit.py"

#define SAFE_PATH "PATH=/usr/sbin:/usr/bin:/sbin:/bin"

/* The child keeps euid 0 under sudo, pkexec and the polkit agent, so it gets
 * SAFE_PATH and these only: SSH_* for session detection, HOME for dconf.
 * Nothing that makes python or glib load code (PYTHONPATH, LD_*, GIO_*...). */
static const char *const forwarded_env[] = {
    "SSH_CLIENT", "SSH_CONNECTION", "SSH_TTY", "SSH_ORIGINAL_COMMAND", "HOME",
};

#define FORWARDED_COUNT (sizeof(forwarded_env) / sizeof(forwarded_env[0]))

static char *env_entry(const char *name, const char *value) {
    size_t size = strlen(name) + strlen(value) + 2;
    char *entry = malloc(size);

    if (entry)
        snprintf(entry, size, "%s=%s", name, value);
    return entry;
}

static void free_env(char **envp) {
    int i;

    if (!envp) return;
    for (i = 0; envp[i]; i++)
        free(envp[i]);
    free(envp);
}

/* Built before the fork: the child must not malloc() or setenv(). */
static char **build_child_env(const char *user, const char *service) {
    /* SAFE_PATH + PAM_USER + PAM_SERVICE + forwarded + NULL */
    char **envp = calloc(FORWARDED_COUNT + 4, sizeof(char *));
    size_t n = 0, i;

    if (!envp) return NULL;

    if (!(envp[n++] = strdup(SAFE_PATH))) goto fail;
    if (!(envp[n++] = env_entry("PAM_USER", user))) goto fail;
    if (!(envp[n++] = env_entry("PAM_SERVICE", service))) goto fail;

    for (i = 0; i < FORWARDED_COUNT; i++) {
        const char *value = getenv(forwarded_env[i]);

        if (value && !(envp[n++] = env_entry(forwarded_env[i], value)))
            goto fail;
    }

    envp[n] = NULL;
    return envp;

fail:
    free_env(envp);
    return NULL;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *user;
    const char *service;
    int ret;
    pid_t pid;
    int status = 0;
    char **args;
    char **envp;
    int i;
    
    // Get username
    ret = pam_get_user(pamh, &user, NULL);
    if (ret != PAM_SUCCESS) return ret;
    
    // Get service name
    ret = pam_get_item(pamh, PAM_SERVICE, (const void **)&service);
    if (ret != PAM_SUCCESS) service = "unknown";
    
    // Prepare arguments: python3 script user service arg1 arg2 ...
    args = malloc((argc + 5) * sizeof(char*));
    if (!args) return PAM_BUF_ERR;
    
    args[0] = PYTHON_EXECUTABLE;
    args[1] = PYTHON_SCRIPT;
    args[2] = (char*)user;
    args[3] = (char*)service;
    
    // Copy PAM module arguments
    for (i = 0; i < argc; i++) {
        args[i + 4] = (char*)argv[i];
    }
    args[argc + 4] = NULL;

    envp = build_child_env(user, service);
    if (!envp) {
        free(args);
        return PAM_BUF_ERR;
    }

    // Fork and execute Python script
    pid = fork();
    if (pid == 0) {
        // Child process

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

        execve(PYTHON_EXECUTABLE, args, envp);

        // Not exit(): the caller's stdio buffers and atexit() handlers are ours too.
        _exit(PAM_AUTHINFO_UNAVAIL);
    } else if (pid > 0) {
        // Parent process - wait for child
        free(args);
        free_env(envp);

        // PAM callers have signal handlers installed; giving up on EINTR
        // would leave status unread.
        while (waitpid(pid, &status, 0) < 0) {
            if (errno != EINTR)
                return PAM_AUTHINFO_UNAVAIL;
        }
        
        if (WIFEXITED(status)) {
            int exit_code = WEXITSTATUS(status);
            switch (exit_code) {
                case PAM_AUTHINFO_UNAVAIL: return PAM_AUTHINFO_UNAVAIL;
                default: return PAM_IGNORE;
            }
        }
    } else {
        // Fork failed
        free(args);
        free_env(envp);
        return PAM_SYSTEM_ERR;
    }
    
    return PAM_AUTHINFO_UNAVAIL;
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
