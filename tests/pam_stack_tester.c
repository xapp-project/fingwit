/*
 * pam_stack_tester - run a PAM auth stack and report what it returned.
 *
 * Used by pam_stack_check.sh to exercise pam_fingwit.so through libpam's own
 * dispatcher, jump semantics included.
 *
 * usage: pam_stack_tester <service> <user>
 */
#include <security/pam_appl.h>
#include <stdio.h>

static int null_conv(int num_msg, const struct pam_message **msg,
                     struct pam_response **resp, void *appdata_ptr) {
    (void)num_msg; (void)msg; (void)resp; (void)appdata_ptr;
    return PAM_CONV_ERR;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s <service> <user>\n", argv[0]);
        return 2;
    }

    struct pam_conv conv = { null_conv, NULL };
    pam_handle_t *pamh = NULL;

    if (pam_start(argv[1], argv[2], &conv, &pamh) != PAM_SUCCESS) {
        fprintf(stderr, "pam_start failed\n");
        return 2;
    }

    int ret = pam_authenticate(pamh, 0);
    printf("%d\n", ret);
    pam_end(pamh, ret);
    return 0;
}
