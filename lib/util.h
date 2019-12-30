#ifndef _UTILLIB_H_
#define _UTILLIB_H_
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define MAX_LOGS_FILES 10
#define LOG_STDIN "./logs/sdtin"
#define LOG_DEBUG "./logs/debug"
#define LOG_RESPONSE "./logs/response"
#define LOG_REQUEST "./logs/request"
#define LOG_STDERR "./logs/stderr"
#define LOG_STDOUT "./logs/stdout"
#define MAX_LINE_LOG 300

#ifndef DEBUG_ON
#define DEBUG_ON 0
#endif

#define _debug(fmt, ...)                 \
    do {                                 \
        if (DEBUG_ON)                    \
            __debug(fmt, ##__VA_ARGS__); \
    } while (0)
#define _debug_info(fmt, ...)                 \
    do {                                      \
        if (DEBUG_ON)                         \
            __debug_info(fmt, ##__VA_ARGS__); \
    } while (0)
#define _debug_request(id_request, request, size_request)       \
    do {                                                        \
        if (DEBUG_ON)                                           \
            __debug_request(id_request, request, size_request); \
    } while (0)

#define _debug_response(id_request, response, size_response)       \
    do {                                                           \
        if (DEBUG_ON)                                              \
            __debug_response(id_request, response, size_response); \
    } while (0)

extern int why_child_exited(pid_t, int);
extern void die(const char *, ...);
extern void __debug(const char *, ...);
extern void vdebug(const char *, va_list);
extern void __debug_info(const char *format, ...);
extern void vdebug_info(const char *format, va_list);
extern void __debug_response(int, char *, int);
extern void __debug_request(int, char *, int);
extern int fd_log(char *);
extern int close_log(char *);
extern int close_all_log();
extern int open_log(char *);
extern void redirect_std_to_log();
extern void handler_others_on();
extern void handler_others_off();
extern int is_handled(int);
extern void handle_sig_default(int, siginfo_t *, void *);
extern float percent_of_symbols(char *);

static const int number_signals = 16;
static const int signals[number_signals] = {SIGINT, SIGHUP, SIGQUIT, SIGILL, SIGTRAP,
                                            SIGABRT, SIGBUS, SIGFPE, SIGSEGV, SIGPIPE,
                                            SIGTERM, SIGSTKFLT, SIGSTOP, SIGTSTP, SIGUSR2, SIGCHLD};

extern struct logger
{
    char *name;
    int fd;
};

#endif