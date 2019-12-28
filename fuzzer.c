#include "requestlib.h"
#include "util.h"
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define LOG_STDIN "./logs/sdtin"
#define LOG_DEBUG "./logs/debug"

void handle_sig_fuzz(int, siginfo_t *, void *);
void handlers_on_fuzz();
void handlers_off_fuzz();
void handle_sig_server(int, siginfo_t *, void *);
void handlers_on_server();
void handlers_off_server();
void handler_connection_on();
void handler_connection_off();
void handle_sig_connection(int, siginfo_t *, void *);

int connection_pid = -1, fuzzer_pid = -1, server_pid = -1;

void handler_on_connection()
{
    debug_info("Connection Signals ON\n");

    for (int s = 1; s <= 62; s++) {
        if (is_handled(s)) {
            struct sigaction new_action;
            new_action.sa_handler = handle_sig_connection;
            sigemptyset(&new_action.sa_mask);
            new_action.sa_flags = 0;
            sigaction(s, &new_action, NULL);
        }
    }
}

void handler_off_connection()
{
    _debug("Connection Signals OFF | ");
    for (int s = 1; s <= 62; s++) {
        if (is_handled(s)) {
            signal(s, SIG_DFL);
        }
    }
}

void handlers_on_server()
{
    debug_info("Server Signals ON\n");

    struct sigaction new_action;
    new_action.sa_handler = handle_sig_server;
    sigemptyset(&new_action.sa_mask);
    new_action.sa_flags = 0;

    for (int s = 0; s < number_signals; s++) {
        sigaction(signals[s], &new_action, NULL);
    }
}

void handlers_off_server()
{
    _debug("Server Signals OFF | ");
    for (int s = 0; s < number_signals; s++) {
        signal(signals[s], SIG_DFL);
    }
}

void handlers_on_fuzz()
{
    debug_info("Fuzzer Signals ON\n");

    struct sigaction new_action;
    new_action.sa_handler = handle_sig_fuzz;
    sigemptyset(&new_action.sa_mask);
    new_action.sa_flags = 0;

    for (int s = 0; s < number_signals; s++) {
        sigaction(signals[s], &new_action, NULL);
    }
}

void handlers_off_fuzz()
{
    _debug("Signals Fuzzer OFF | ");
    for (int s = 0; s < number_signals; s++) {
        signal(signals[s], SIG_DFL);
    }
}

void handle_sig_server(int sig, siginfo_t *si, void *ucontext)
{
    debug_info("Server | Handling signal --%s-- (%d) | ", sys_siglist[sig],
               getpid());
    handlers_off_server();
    if (sig != SIGUSR2) {
        if (sig == SIGCHLD) {
            pid_t chld;
            int status;

            while ((chld = waitpid(WAIT_ANY, &status, WUNTRACED | WNOHANG)) !=
                   -1)
                ;

            int signal_chld = why_child_exited(chld, status);
            if (signal_chld == 0) {
                _debug("Child %d exit OK, raising SIGINT to this process(SERVER)\n",
                       chld);
                raise(SIGINT);
                return;
            }

            _debug("Sending signal %d to this process(SERVER)", signal_chld);
            handlers_on_server();
            kill(getpid(), signal_chld);
            return;
        } else {
            _debug("Sending/Raising signal to everyone (%d, %d, %d)\n", fuzzer_pid, getpid(), connection_pid);
            if (connection_pid != -1)
                kill(connection_pid, sig);
            kill(fuzzer_pid, sig);
            raise(sig);
            return;
        }
    } else {
        union sigval sv;

        if (si != NULL)
            sv.sival_int = si->si_value.sival_int;
        else
            sv.sival_int = 0xD1E;

        if (connection_pid != -1) {
            _debug("Queueing %s to %d because SIGUSR2", sys_siglist[SIGINT],
                   connection_pid);
            sigqueue(connection_pid, SIGINT, sv);
        }

        _debug("Queueing %s to %d because SIGUSR2", sys_siglist[sig],
               sys_siglist[SIGINT], getpid());
        sigqueue(getpid(), SIGINT, sv); // TODO podrian ser equivalentes

        _debug("Queueing %s to %d because SIGUSR2", sys_siglist[sig],
               sys_siglist[SIGINT], server_pid);

        sigqueue(server_pid, SIGUSR2, sv); // TODO podrian ser equivalentes
    }

    _debug(" | End\n");
}

void handle_sig_fuzz(int sig, siginfo_t *si, void *ucontext)
{
    debug_info("Fuzzer | Handling signal --%s-- (%d) | ", sys_siglist[sig],
               getpid());
    handlers_off_fuzz();

    if (sig != SIGUSR2) {
        if (sig == SIGCHLD) {
            pid_t chld;
            int status;
            while ((chld = waitpid(WAIT_ANY, &status, WUNTRACED | WNOHANG)) !=
                   -1)
                ;

            int signal_chld = why_child_exited(chld, status);

            if (signal_chld == 0) {
                _debug("Child %d exit OK, raising SIGCONT to this process (FUZZ)\n",
                       chld);
                //raise(SIGCONT);
                handlers_on_fuzz();
                return;
            }

            _debug("Raising signal %d to this process(FUZZ)\n", signal_chld);
            handlers_on_fuzz();
            raise(signal_chld);
            return;
        } else {
            _debug("Sending/Raising signal to everyone(%d, %d, %d)\n", fuzzer_pid, server_pid, connection_pid);
            if (connection_pid != -1)
                kill(connection_pid, sig);
            kill(server_pid, sig);
            //close_all_log();
            raise(sig);
            return;
        }
    } else {
        union sigval sv;

        if (si != NULL)
            sv.sival_int = si->si_value.sival_int;
        else
            sv.sival_int = 0xD1E;

        if (connection_pid != -1) {
            _debug("Queueing %s to %d because SIGUSR2", sys_siglist[SIGINT],
                   connection_pid);
            sigqueue(connection_pid, SIGINT, sv);
        }

        _debug("Queueing %s to %d because SIGUSR2", sys_siglist[sig],
               sys_siglist[SIGINT], getpid());
        sigqueue(getpid(), SIGINT, sv); // TODO podrian ser equivalentes

        _debug("Queueing %s to %d because SIGUSR2", sys_siglist[sig],
               sys_siglist[SIGINT], server_pid);

        sigqueue(server_pid, SIGUSR2, sv); // TODO podrian ser equivalentes
    }

    _debug(" | End\n");
}

void handle_sig_connection(int sig, siginfo_t *si, void *ucontext)
{
    debug_info("CONN | Handling signal --%s-- (%d) | ", sys_siglist[sig],
               getpid());
    handler_off_connection();

    if (sig != SIGUSR2) {
        if (sig == SIGCHLD) {
            pid_t chld;
            int status;
            while ((chld = waitpid(WAIT_ANY, &status, WUNTRACED | WNOHANG)) !=
                   -1)
                ;

            int signal_chld = why_child_exited(chld, status);

            if (signal_chld == 0) {
                _debug("Child %d exit OK, raising SIGINT to this proces (CONN)\n", chld);
                raise(SIGINT);
                return;
            }

            _debug("Sending singal %s to this process(CONN)\n", signal_chld);
            handler_on_connection();
            kill(getpid, signal_chld);

            return;
        } else {
            _debug("Sending/Raising signal to everyone(%d, %d, %d)\n", fuzzer_pid, server_pid, getpid());
            if (connection_pid != -1)
                kill(connection_pid, sig);
            kill(server_pid, sig);
            raise(sig);
            return;
        }
    } else {
        union sigval sv;

        if (si != NULL)
            sv.sival_int = si->si_value.sival_int;
        else
            sv.sival_int = 0xD1E;

        if (connection_pid != -1) {
            _debug("Queueing %s to %d because SIGUSR2", sys_siglist[SIGINT],
                   connection_pid);
            sigqueue(connection_pid, SIGINT, sv);
        }

        _debug("Queueing %s to %d because SIGUSR2", sys_siglist[sig],
               sys_siglist[SIGINT], getpid());
        sigqueue(getpid(), SIGINT, sv); // TODO podrian ser equivalentes

        _debug("Queueing %s to %d because SIGUSR2", sys_siglist[sig],
               sys_siglist[SIGINT], server_pid);

        sigqueue(server_pid, SIGUSR2, sv); // TODO podrian ser equivalentes
    }

    _debug("| End\n");
}

int main(int argc, char **argv)
{
    srand(time(NULL));

    open_log(LOG_DEBUG);
    open_log(LOG_REQUEST);
    open_log(LOG_RESPONSE);

    fuzzer_pid = getpid();
    handler_others_on();
    debug_info("Write something:\n");

    if ((server_pid = fork()) != 0) // PARENT: fuzzer
    {
        sleep(1); // waiting server UP

        handlers_on_fuzz();
        int loop = 0;
        while (__AFL_LOOP(1000000)) {
            //while (1) {
            loop++;
            char buf[MAX_SIZE_REQUEST + 1];
            const int chunk_size = 1000;
            int max_reads = MAX_SIZE_REQUEST / chunk_size;
            ssize_t size_request = 0, size_partial;
            memset(buf, 0, MAX_SIZE_REQUEST);

            debug_info("(loop:%d) Reading stdin...\n", loop);
            for (;;) {
                if (max_reads <= 0)
                    break;
                max_reads--;
                size_partial = read(0, buf + size_request, chunk_size);
                if (size_partial > 0) {
                    //TODO debug_info("(loop:%d) Reading chunk...%d\n", loop,
                    //          chunk_size);
                    size_request += size_partial;
                } else if (size_partial < 0) {
                    if (errno != EINTR) {
                        //buf[size_request + 1] = '\0';
                        debug_info("(loop:%d) STDIN ERROR (%s)\n", loop,
                                   strerror(errno));
                        die("Error reading request [read:%d, errno: %s]\n",
                            size_request, strerror(errno));
                    }
                } else {
                    //buf[size_request + 1] = '\0';
                    //debug_info("(loop:%d) REQUEST [size: %d]\n", loop,
                    //           size_request);
                    break;
                }
            }
            if (size_request + 7 < MAX_SIZE_REQUEST) {
                buf[size_request] = '\r';
                buf[size_request + 1] = '\n';
                buf[size_request + 2] = '\r';
                buf[size_request + 3] = '\n';
                buf[size_request + 4] = '\r';
                buf[size_request + 5] = '\n';
                buf[size_request + 6] = '\0';
                size_request += 7;
            } else {
                debug_info("(loop:%d) MAX_SIZE_REQUEST\n", loop);
                buf[size_request - 6] = '\r';
                buf[size_request - 5] = '\n';
                buf[MAX_SIZE_REQUEST - 4] = '\r';
                buf[MAX_SIZE_REQUEST - 3] = '\n';
                buf[MAX_SIZE_REQUEST - 2] = '\r';
                buf[MAX_SIZE_REQUEST - 1] = '\n';
                buf[MAX_SIZE_REQUEST - 0] = '\0';
                size_request = MAX_SIZE_REQUEST;
            }

            debug_info("(loop:%d) sending... (size: %d)\n", loop, size_request);
            //int s_r = send_request(buf, size_request);
            int s_r = send_request_stochastic(buf, size_request);
            if (s_r < 0)
                debug_info("(loop:%d) sending error:%d\n", loop, s_r);
        }

        debug_info("(loop:%d) | Final Loop\n", loop);
        kill(server_pid, SIGINT);
        sleep(1);
        close_all_log();
        return 0;
    } else // CHILD: HTTP SERVER
    {
        server_pid = getpid(); // remove
        int status = 0;
        if ((connection_pid = fork()) == 0) {
            connection_pid = getpid();
            debug_info("Calling mini_httpd with args: ");
            for (int c = 1; c < argc; c++) {
                _debug("arg[%d]=%s ", c, argv[c]);
            }
            _debug("\n");
            indirect_main(argc, argv);
            /*if (execve("./httpd", NULL, NULL) < 0) {
                perror("error");
            }
            */
        } else {
            handlers_on_server();

            //handler_on_connection();

            while (1) {
                debug_info("Server-Fork | Sleeping\n");
                if (sleep(1000) != 0)
                    debug_info("Server-Fork | waken from sleep for handling a signal\n");
            }
            return 0;
        }
    }
    return 0;
}
