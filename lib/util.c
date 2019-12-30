#include "util.h"

struct logger *loggers[MAX_LOGS_FILES];

void redirect_std_to_log()
{
    int fd_err = open_log(LOG_STDERR);
    int fd_out = open_log(LOG_STDOUT);

    if (dup2(fd_err, STDERR_FILENO) < 0) {
        _debug_info("cannot redirect stderr to %s, error: %s", LOG_STDERR, strerror(errno));
    }
    if (dup2(fd_out, STDOUT_FILENO) < 0) {
        _debug_info("cannot redirect stderr to %s, error: %s", LOG_STDOUT, strerror(errno));
    }

    return;
}

float percent_of_symbols(char *string)
{
    float total = 0, symbols = 0;
    char *c = string;
    if (*c == '\0')
        return 0;
    while (*c) {
        total++;
        if ((*c < 0x20 || *c > 0x7e) && *c != '\n' && *c != '\r') {
            symbols++;
        }
        c++;
    }

    return (float)(symbols / total);
}

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

void __debug(const char *format, ...)
{
    va_list vargs;
    va_start(vargs, format);
    vdebug(format, vargs);
    va_end(vargs);
}

void __debug_info(const char *format, ...)
{
    va_list vargs;
    va_start(vargs, format);
    vdebug_info(format, vargs);
    va_end(vargs);
}

void vdebug_info(const char *format, va_list argp)
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

void die(const char *format, ...)
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
    _debug_info("Closing all logs\n");
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
            _debug("[pid: %d exited] status=%d | ",
                   child,
                   WEXITSTATUS(status));
            return 0;
        } else if (WIFSIGNALED(status)) {
            _debug("[pid: %d killed by signal (%d) %s] | ",
                   child,
                   WTERMSIG(status),
                   sys_siglist[WTERMSIG(status)]);
            return WTERMSIG(status);
        } else if (WIFSTOPPED(status)) {
            _debug("[pid: %d stopped by signal (%d) %s] | ",
                   child,
                   WSTOPSIG(status),
                   sys_siglist[WSTOPSIG(status)]);
            return WSTOPSIG(status);
        } else if (WIFCONTINUED(status)) {
            _debug("[pid: %d continued] | ", child);
        }
    } while (!WIFEXITED(status) && !WIFSIGNALED(status));

    return 1;
}

void __debug_request(int id_request, char *request, int size_request)
{
    int fd = fd_log(LOG_REQUEST);
    if (fd <= 0) {
        fprintf(stderr, "fd not found for %s", LOG_REQUEST);
        exit(-1);
    }
    char header_log[100];
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    char t_s[64];
    assert(strftime(t_s, sizeof(t_s), "[%x %X]", tm));
    snprintf(header_log, 100, "\n(id:%d, size:%d date:%s)", id_request, size_request, t_s);
    if (write(fd, header_log, strlen(header_log)) < 0)
        perror("Writting error");
    //char req[300];
    //snprintf(req, 300, "\n\n%s  [cut]\n\n", request);
    //if (write(fd, req, strlen(req)) < 0)
    //    perror("Writting error");
    if (write(fd, request, size_request) < 0)
        perror("Writting error");
}

void __debug_response(int id_response, char *response, int size_response)
{
    int fd = fd_log(LOG_RESPONSE);
    if (fd <= 0) {
        fprintf(stderr, "fd not found for %s", LOG_RESPONSE);
        exit(-1);
    }
    char header_log[100];
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    char t_s[64];
    assert(strftime(t_s, sizeof(t_s), "[%x %X]", tm));
    snprintf(header_log, 100, "\n(id:%d, size:%d date:%s)", id_response, size_response, t_s);
    if (write(fd, header_log, strlen(header_log)) < 0)
        perror("Writting error");

    //char req[300];
    //snprintf(req, 300, "\n\n%s  [cut]\n\n", response);
    //if (write(fd, req, strlen(req)) < 0)
    //    perror("Writting error");
    if (size_response == 0) {
        char sizezero[100];
        snprintf(sizezero, 100, "SIZEZERO (timeout?)\n\n", response);
        if (write(fd, sizezero, strlen(sizezero)) < 0)
            perror("Writting error");
    } else {
        if (write(fd, response, size_response) < 0)
            perror("Writting error");
    }
}

void handler_others_on()
{
    _debug_info("xxxx | Other signals ON\n");
    for (int s = 1; s <= 62; s++) {
        if (!is_handled(s)) {
            struct sigaction new_action;
            new_action.sa_handler = handle_sig_default;
            sigemptyset(&new_action.sa_mask);
            new_action.sa_flags = 0;
            sigaction(s, &new_action, NULL);
        }
    }
}

void handler_others_off()
{
    _debug_info("xxxx | Other signals OFF\n");
    for (int s = 1; s <= 62; s++) {
        if (!is_handled(s)) {
            signal(s, SIG_DFL);
        }
    }
}

int is_handled(int sig)
{
    for (int s = 0; s < number_signals; s++)
        if (signals[s] == sig)
            return 1;
    return 0;
}

void handle_sig_default(int sig, siginfo_t *si, void *ucontext)
{
    _debug_info("HTTPD | Unhandle %s\n", sys_siglist[sig]);
}
