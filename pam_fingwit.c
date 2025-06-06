/*
 * pam_fingwit - Smart fingerprint PAM module
 * C wrapper for Python implementation
 */

#include <security/pam_modules.h>
#include <security/pam_appl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <string.h>
#include <stdio.h>

#define PYTHON_SCRIPT PYTHON_SCRIPT_DIR "/pam_fingwit.py"

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *user;
    const char *service;
    int ret;
    pid_t pid;
    int status;
    char **args;
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
    
    args[0] = "python3";
    args[1] = PYTHON_SCRIPT;
    args[2] = (char*)user;
    args[3] = (char*)service;
    
    // Copy PAM module arguments
    for (i = 0; i < argc; i++) {
        args[i + 4] = (char*)argv[i];
    }
    args[argc + 4] = NULL;
    
    // Fork and execute Python script
    pid = fork();
    if (pid == 0) {
        // Child process
        setenv("PAM_USER", user, 1);
        setenv("PAM_SERVICE", service, 1);
        
        execvp("python3", args);
        exit(PAM_AUTHINFO_UNAVAIL);
    } else if (pid > 0) {
        // Parent process - wait for child
        free(args);
        waitpid(pid, &status, 0);
        
        if (WIFEXITED(status)) {
            int exit_code = WEXITSTATUS(status);
            switch (exit_code) {
                case 0: return PAM_SUCCESS;
                case 7: return PAM_AUTH_ERR;
                case 9: return PAM_AUTHINFO_UNAVAIL;
                case 10: return PAM_USER_UNKNOWN;
                default: return PAM_AUTHINFO_UNAVAIL;
            }
        }
    } else {
        // Fork failed
        free(args);
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