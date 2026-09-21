/*
 * pam_driver - test driver for pam_fingwit.so
 *
 * usage: pam_driver <module.so> <service> <user> [module args...]
 *
 * Loads the module and calls pam_sm_authenticate() with a real pam_handle_t,
 * printing the raw PAM return code. Two knobs reproduce conditions the module
 * has to survive:
 *
 *   FINGWIT_DRIVER_ALARM_MS      interrupt the module's wait with a
 *                                non-restarting SIGALRM after this long
 *   FINGWIT_DRIVER_BUFFERED_LOG  leave a marker unflushed in this file, so a
 *                                child leaving through exit() writes it twice
 */
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <dlfcn.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>

static void on_alarm(int signum) {
    (void)signum;
}

static void arm_alarm(long ms) {
    struct sigaction sa;
    struct itimerval timer;

    /* No SA_RESTART: the point is to make waitpid() fail with EINTR. */
    sa.sa_handler = on_alarm;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGALRM, &sa, NULL);

    timer.it_value.tv_sec = ms / 1000;
    timer.it_value.tv_usec = (ms % 1000) * 1000;
    timer.it_interval.tv_sec = 0;
    timer.it_interval.tv_usec = 0;
    setitimer(ITIMER_REAL, &timer, NULL);
}

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

    const char *log_path = getenv("FINGWIT_DRIVER_BUFFERED_LOG");
    if (log_path) {
        FILE *log = fopen(log_path, "w");
        if (log) {
            /* Deliberately left unflushed and open. */
            fprintf(log, "marker\n");
        }
    }

    const char *alarm_ms = getenv("FINGWIT_DRIVER_ALARM_MS");
    if (alarm_ms)
        arm_alarm(atol(alarm_ms));

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
