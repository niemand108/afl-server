#ifndef _HTTPDSIGLIB_H_
#define _HTTPDSIGLIB_H_

#include "util.h"
#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#define LOG_DEBUG_HTTPD "./logs/debug-httpd"

static int server_pid_httpdlib = -1, conn_pid_httpdlib = -1;
extern void handle_sig(int, siginfo_t *, void *);
extern void handlers_httpd_on();
extern void handlers_httpd_off();
extern void debug_httpd(const char *, ...);
extern inline void set_server_pid(pid_t);
extern inline pid_t get_server_pid();
extern inline void set_conn_pid(pid_t);
extern inline pid_t get_conn_pid();

#endif