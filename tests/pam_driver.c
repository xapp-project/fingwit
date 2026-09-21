/*
 * pam_driver - test driver for pam_fingwit.so
 *
 * usage: pam_driver <module.so> <service> <user> [module args...]
 *
 * Loads the module and calls pam_sm_authenticate() with a real pam_handle_t,
 * printing the raw PAM return code, without installing anything into
 * /etc/pam.d or going through the PAM stack's jump semantics.
 */
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <dlfcn.h>
#include <stdio.h>

static int null_conv(int num_msg, const struct pam_message **msg,
                     struct pam_response **resp, void *appdata_ptr) {
    (void)num_msg; (void)msg; (void)resp; (void)appdata_ptr;
    return PAM_CONV_ERR;
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: %s <module.so> <service> <user> [module args...]\n", argv[0]);
        return 2;
    }

    struct pam_conv conv = { null_conv, NULL };
    pam_handle_t *pamh = NULL;
    int ret = pam_start(argv[2], argv[3], &conv, &pamh);
    if (ret != PAM_SUCCESS) {
        fprintf(stderr, "pam_start failed: %d\n", ret);
        return 2;
    }

    void *handle = dlopen(argv[1], RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        return 2;
    }

    int (*authenticate)(pam_handle_t *, int, int, const char **) =
        dlsym(handle, "pam_sm_authenticate");
    if (!authenticate) {
        fprintf(stderr, "dlsym failed: %s\n", dlerror());
        return 2;
    }

    ret = authenticate(pamh, 0, argc - 4, (const char **)&argv[4]);
    printf("%d\n", ret);

    pam_end(pamh, ret);
    return 0;
}
