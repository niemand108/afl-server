#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAX_LOGS_FILES 10
#define LOG_STDIN "./logs/sdtin"
#define LOG_DEBUG "./logs/debug"
#define LOG_RESPONSE "./logs/response"
#define LOG_REQUEST "./logs/request"
#define MAX_LINE_LOG 300

int why_child_exited(pid_t, int);
static void die(const char *, ...);
static void debug(const char *, ...);
static void vdebug(const char *, va_list);
static void debug_info(const char *format, ...);
static void vdebug_info(const char *format, va_list);

static void debug_response(int, char *, int);
static void debug_request(int, char *, int);
int fd_log(char *);
int close_log(char *);
int close_all_log();
int open_log(char *);

const int number_signals = 16;
int signals[number_signals] = {SIGINT, SIGHUP, SIGQUIT, SIGILL, SIGTRAP,
                               SIGABRT, SIGBUS, SIGFPE, SIGSEGV, SIGPIPE,
                               SIGTERM, SIGSTKFLT, SIGSTOP, SIGTSTP, SIGUSR2, SIGCHLD};

struct logger
{
    char *name;
    int fd;
};

struct logger *loggers[MAX_LOGS_FILES];

void vdebug(const char *format, va_list argp)
{
    int fd = fd_log(LOG_DEBUG);
    if (fd <= 0) {
        fprintf(stderr, "fd not found for %s", LOG_DEBUG);
        exit(-1);
    }
    if (argp != NULL) {
        char log[MAX_LINE_LOG];

        vsnprintf(log, MAX_LINE_LOG, format, argp);
        printf("%s", log);
        if (write(fd, log, strlen(log)) < 0)
            perror("Writting error");
    } else {
        printf("%s", format);
        if (write(fd, format, strlen(format)) < 0)
            perror("Writting error");
    }
}

static void debug(const char *format, ...)
{
    va_list vargs;
    va_start(vargs, format);
    vdebug(format, vargs);
    va_end(vargs);
}

static void debug_info(const char *format, ...)
{
    va_list vargs;
    va_start(vargs, format);
    vdebug_info(format, vargs);
    va_end(vargs);
}

static void vdebug_info(const char *format, va_list argp)
{
    int fd = fd_log(LOG_DEBUG);
    if (fd <= 0) {
        fprintf(stderr, "fd not found for %s", LOG_DEBUG);
        exit(-1);
    }

    char log[MAX_LINE_LOG];
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    char t_s[64];
    assert(strftime(t_s, sizeof(t_s), "[%x %X]", tm));
    snprintf(log, MAX_LINE_LOG, "%s [pid:%d] ", t_s, getpid());
    printf("%s", log);

    if (write(fd, log, strlen(log)) < 0)
        perror("Writting error");

    if (argp != NULL) {
        vsnprintf(log, MAX_LINE_LOG, format, argp);
        printf("%s", log);
        if (write(fd, log, strlen(log)) < 0)
            perror("Writting error");
    } else {
        printf("%s", format);
        if (write(fd, format, strlen(format)) < 0)
            perror("Writting error");
    }
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
    vdebug(format, vargs);
    va_end(vargs);
    exit(-1);
}
int open_log(char *logname)
{
    int fd = fd_log(logname);
    if (fd <= 0) {
        perror("error in open log");
        exit(-1);
    } else
        return fd;
}

int fd_log(char *log_name)
{
    int l = 0;
    for (l = 0; l < MAX_LOGS_FILES; l++) {
        if (loggers[l] == NULL) {
            break;
        }

        if (strcmp(log_name, loggers[l]->name) == 0) {
            if (loggers[l]->fd >= 0) {
                return loggers[l]->fd;
            }
        } else {
            continue;
        }
    }

    if (l >= MAX_LOGS_FILES) {
        fprintf(stderr, "MAXLOGFILES reached");
        return -1;
    }

    int fd;

    if ((fd = open(log_name, O_WRONLY | O_CREAT | O_APPEND, 0755)) < 0) {
        perror("error opening log");
        return -1;
    }
    loggers[l] = (struct logger *)malloc(sizeof(struct logger));
    loggers[l]->name = (char *)malloc(strlen(log_name) + 1);
    strcpy(loggers[l]->name, log_name);
    loggers[l]->fd = fd;
    return loggers[l]->fd;
}

int close_log(char *log_name)
{
    for (int l = 0; l < MAX_LOGS_FILES; l++) {
        if (strcmp(log_name, loggers[l]->name) == 0) {
            if (loggers[l]->fd >= 0) {
                return close(loggers[l]->fd);
            }
        }
    }
}

int close_all_log()
{
    debug_info("Closing all logs\n");
    for (int l = 0; l < MAX_LOGS_FILES; l++) {
        if (loggers[l] != NULL && loggers[l]->fd >= 0) {
            close(loggers[l]->fd);
        }
    }
}

int why_child_exited(pid_t child, int status)
{
    do {
        if (WIFEXITED(status)) {
            debug("[pid: %d exited] status=%d | ",
                  child,
                  WEXITSTATUS(status));
            return 0;
        } else if (WIFSIGNALED(status)) {
            debug("[pid: %d killed by signal (%d) %s] | ",
                  child,
                  WTERMSIG(status),
                  sys_siglist[WTERMSIG(status)]);
            return WTERMSIG(status);
        } else if (WIFSTOPPED(status)) {
            debug("[pid: %d stopped by signal (%d) %s] | ",
                  child,
                  WSTOPSIG(status),
                  sys_siglist[WSTOPSIG(status)]);
            return WSTOPSIG(status);
        } else if (WIFCONTINUED(status)) {
            debug("[pid: %d continued] | ", child);
        }
    } while (!WIFEXITED(status) && !WIFSIGNALED(status));

    return 1;
}

static void debug_request(int id_request, char *request, int size_request)
{
    int fd = fd_log(LOG_REQUEST);
    if (fd <= 0) {
        fprintf(stderr, "fd not found for %s", LOG_REQUEST);
        exit(-1);
    }
    char header_log[100];
    snprintf(header_log, 100, "\n(id:%d, size:%d\n)", id_request, size_request);
    if (write(fd, request, size_request) < 0)
        perror("Writting error");
}

static void debug_response(int id_response, char *response, int size_response)
{
    int fd = fd_log(LOG_RESPONSE);
    if (fd <= 0) {
        fprintf(stderr, "fd not found for %s", LOG_RESPONSE);
        exit(-1);
    }
    char header_log[100];
    snprintf(header_log, 100, "\n(id:%d, size:%d\n)", id_response, size_response);
    if (write(fd, response, size_response) < 0)
        perror("Writting error");
}
