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
#define MAX_LINE_LOG 300

extern int why_child_exited(pid_t, int);
extern void die(const char *, ...);
extern void _debug(const char *, ...);
extern void vdebug(const char *, va_list);
extern void debug_info(const char *format, ...);
extern void vdebug_info(const char *format, va_list);
extern void debug_response(int, char *, int);
extern void debug_request(int, char *, int);
extern int fd_log(char *);
extern int close_log(char *);
extern int close_all_log();
extern int open_log(char *);
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