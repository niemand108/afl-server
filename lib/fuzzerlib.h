#ifndef _FUZZERLIB_H_
#define _FUZZERLIB_H_

#include "util.h"
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>

#define LOG_STDIN "./logs/sdtin"
#define LOG_DEBUG "./logs/debug"

extern void handle_sig_fuzz(int, siginfo_t *, void *);
extern void handlers_on_fuzz();
extern void handlers_off_fuzz();
extern void handle_sig_server(int, siginfo_t *, void *);
extern void handlers_on_server();
extern void handlers_off_server();
extern void handler_connection_on();
extern void handler_connection_off();
extern void handle_sig_connection(int, siginfo_t *, void *);
extern inline void set_fuzz_server_pid(pid_t);
extern inline pid_t get_fuzz_server_pid();
extern inline void set_fuzz_conn_pid(pid_t);
extern inline pid_t get_fucc_conn_pid();
extern inline void set_fuzz_fuzzer_pid(pid_t);
extern inline pid_t get_fucc_fuzzer_pid();

static int connection_pid = -1, fuzzer_pid = -1, server_pid = -1;

#endif