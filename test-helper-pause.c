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
    /* Even a matching caller name must never terminate the credential holder. */
    prctl(PR_SET_NAME, g_helper_name, 0, 0, 0);
    terminate_owned_helpers();
    check(waitpid(test_children[0], &status, 0) == test_children[0], "owned helper exits");
    check(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL, "helper is terminated with SIGKILL");
    test_children[0] = 0;
    check(waitpid(test_children[1], &status, WUNTRACED | WNOHANG) == 0, "other run is untouched");
    char completion_path[] = "helper-completion-XXXXXX";
    int completion_fd = mkstemp(completion_path);
    check(completion_fd >= 0, "create pending completion file");
    close(completion_fd);
    g_completion_path = completion_path;
    finish_run();
    completion_fd = open(completion_path, O_RDONLY);
    unsigned char completed = 0;
    check(completion_fd >= 0 && read(completion_fd, &completed, 1) == 1 && completed == 1,
          "native completion is a binary event, not a log message");
    close(completion_fd);
    unlink(completion_path);
    g_run_finished = 0;
    finish_run();
    check(access(completion_path, F_OK) != 0, "late completion cannot recreate a removed file");
    alarm(0);
    puts("PASS: owned helper killed; caller/other run unchanged; completion protocol verified");
    return 0;
}
