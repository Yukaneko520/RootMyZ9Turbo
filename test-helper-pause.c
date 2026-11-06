/* Linux/Android lifecycle test only; never invokes the Timer payload main. */
#define main timer_payload_main
#include "timer.c"
#undef main

static pid_t test_children[2];

static void cleanup_test_children(void)
{
    for (int i = 0; i < 2; i++)
        if (test_children[i] > 0)
        {
            kill(test_children[i], SIGKILL);
            while (waitpid(test_children[i], NULL, 0) < 0 && errno == EINTR) {}
        }
}

static void test_timeout(int signal)
{
    (void)signal;
    cleanup_test_children();
    _exit(124);
}

static void check(int condition, const char *message)
{
    if (!condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

int main(void)
{
    int ready[2], status = 0;
    snprintf(g_helper_name, sizeof(g_helper_name), "tzh-%d", getpid());
    check(pipe(ready) == 0, "create readiness pipe");
    atexit(cleanup_test_children);
    signal(SIGALRM, test_timeout);
    alarm(5);
    for (int i = 0; i < 2; i++)
    {
        test_children[i] = fork();
        check(test_children[i] >= 0, "fork test helper");
        if (test_children[i] == 0)
        {
            prctl(PR_SET_NAME, i == 0 ? g_helper_name : "tzh-other", 0, 0, 0);
            if (write(ready[1], "R", 1) != 1) _exit(1);
            for (;;) pause();
        }
    }
    for (int i = 0; i < 2; i++)
    {
        char marker;
        check(read(ready[0], &marker, 1) == 1, "helper readiness");
    }
    /* Even a matching caller name must never suspend the credential holder. */
    prctl(PR_SET_NAME, g_helper_name, 0, 0, 0);
    pause_owned_helpers();
    check(waitpid(test_children[0], &status, WUNTRACED) == test_children[0], "owned helper stops");
    check(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP, "helper is suspended, not terminated");
    check(waitpid(test_children[1], &status, WUNTRACED | WNOHANG) == 0, "other run is untouched");
    check(kill(test_children[0], SIGCONT) == 0, "suspension is reversible");
    alarm(0);
    puts("PASS: owned helper paused; other helper and caller unchanged");
    return 0;
}
