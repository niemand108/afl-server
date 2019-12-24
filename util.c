#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/wait.h>
#include <string.h>
#include <errno.h>

#define LOG_STDIN "./logs/sdtin"
#define LOG_DEBUG "./logs/debug"

int why_child_exited(pid_t, int, char *, ...);
static void debug(const char *, ...);
static void die(const char *, ...);
static void debug_to(char *, char *);

const int number_signals = 16;
int signals[number_signals] = {SIGINT, SIGHUP, SIGQUIT, SIGILL, SIGTRAP,
                               SIGABRT, SIGBUS, SIGFPE, SIGSEGV, SIGPIPE,
                               SIGTERM, SIGSTKFLT, SIGSTOP, SIGTSTP, SIGUSR2, SIGCHLD};

static void debug(const char *format, ...)
{
    va_list vargs;
    va_start(vargs, format);
    char log[200];
    vsnprintf(log, 200, format, vargs);
    debug_to(LOG_DEBUG, log);
    va_end(vargs);
}

static void debug_to(char * file_log, char * log)
{
    pid_t actual_pid = getpid();
    FILE *fptr;
    fptr = fopen(file_log, "a");
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    char t_s[64];
    assert(strftime(t_s, sizeof(t_s), "[%x %X]", tm));
    printf("%s [pid:%d] ", t_s, actual_pid);
    printf(log);
    printf("\n");
    fprintf(fptr, "%s [pid:%d] ", t_s, actual_pid);
    fprintf(fptr, log);
    fprintf(fptr, ".\n");
    fclose(fptr);
}

static void die(const char *format, ...)
{
    va_list vargs;
    va_start(vargs, format);
    fprintf(stderr, "DIE: ");
    vfprintf(stderr, format, vargs);
    fprintf(stderr, ".\n");
    va_end(vargs);
    va_start(vargs, format);
    debug(format, vargs);
    va_end(vargs);
    exit(-1);
}

int why_child_exited(pid_t child, int status, char *format_log, ...)
{
    va_list vargs;
    va_start(vargs, format_log);
    char format_header[100];
    snprintf(format_header, 100, format_log, vargs);
    va_end(vargs);

    do { 
        if (WIFEXITED(status)) {
            debug("%s [pid: %d exited] status=%d", format_header, child, WEXITSTATUS(status));
            return 0;
        }
        else if (WIFSIGNALED(status))
        {
            debug("%s [pid: %d killed by signal %s (%d)]", \
                    format_header, child, sys_siglist[WTERMSIG(status)], WTERMSIG(status));
            return WTERMSIG(status);
        }
        else if (WIFSTOPPED(status))
        {
            debug("%s [pid: %d stopped by signal %s (%s)]",\
                    format_header, child, sys_siglist[WSTOPSIG(status)], WSTOPSIG(status));
            return WSTOPSIG(status);
        }
        else if (WIFCONTINUED(status))
        {
            debug("%s [pid: %d continued]", format_header, child);
        }
    } while (!WIFEXITED(status) && !WIFSIGNALED(status));
    
    return 1;
}