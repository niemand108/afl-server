#include "util.c"
#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define MAX_SIZE_REQUEST 200000
#define MAX_SIZE_RESPONSE 200000
#define HOSTNAME_HTTPD 0 /* localhost */
#define PORTNAME_HTTPD "http"

pid_t fuzzer_pid = -1, server_pid = -1, connection_pid = -1;

void handle_sig_fuzz(int, siginfo_t *, void *);
void handlers_on_fuzz();
void handlers_off_fuzz();
void handle_sig_server(int, siginfo_t *, void *);
void handlers_on_server();
void handlers_off_server();
void handler_connection_on();
void handler_connection_off();
void handle_sig_connection(int, siginfo_t *, void *);
void handle_sig_default(int, siginfo_t *, void *);
void handler_default_on();
void handler_default_off();
int send_request(char *, size_t);
static void die(const char *format, ...);

int send_request(char *request, size_t size_request)
{
    const char *hostname = HOSTNAME_HTTPD;
    const char *portname = PORTNAME_HTTPD;
    struct addrinfo hints;
    int id_request = rand();

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = 0;
    hints.ai_flags = AI_ADDRCONFIG;
    struct addrinfo *res = 0;

    int err = getaddrinfo(hostname, portname, &hints, &res);
    if (err != 0) {
        die("(id_req: %d) Failed to resolve remote socket address (err=%d)\n",
            id_request, err);
    }

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd == -1) {
        die("(id_req: %d) Socket: %s name: %s port:%d\n", id_request,
            strerror(errno), res->ai_canonname, portname);
    }

    debug_info("(id_req: %d) Conectando...\n", id_request);
    if (connect(fd, res->ai_addr, res->ai_addrlen) == -1) {
        die("(id_req: %d) Socket connect: %s\n", id_request, strerror(errno));
    }

    int written;
    if ((written = write(fd, request, size_request)) == -1) {
        debug_info("(id_req: %d) write socket:  %s\n", id_request,
                   strerror(errno));
        return -EAGAIN;
    }
    assert(written == size_request);

    debug_info("(id_req: %d) HTTP REQUEST DONE [written:%d size_request:%d]\n",
               id_request, written, size_request);
    debug_request(id_request, request, size_request);

    freeaddrinfo(res);

    ssize_t size_response = 0, size_partial;
    int chunk_size = 1000;
    int max_resp_reads = MAX_SIZE_RESPONSE / chunk_size;
    char buf_r[MAX_SIZE_RESPONSE + 1];
    memset(buf_r, 0, MAX_SIZE_RESPONSE + 1);

    debug_info("(id_req: %d) Reading response... | ", id_request);
    // TODO: timeout read
    for (;;) {
        if (max_resp_reads <= 0) {
            break;
        }
        size_partial = read(fd, buf_r + size_response, chunk_size);
        if (size_partial > 0) {
            max_resp_reads--;
            size_response += size_partial;
        } else if (size_partial < 0) {
            if (errno != EINTR) {
                debug_info("Partial response [size: %d]\n%s\n(EOF)\n",
                           size_response, buf_r);
                die("Error reading response [read:%d, errno: %s]\n",
                    size_response, strerror(errno));
            }
        } else {
            debug_info("HTTP RESPONSE [size: %d])\n", size_response);
            break;
        }
    }
    assert(size_request < MAX_SIZE_RESPONSE);
    if (buf_r[size_response] != '\0') {
        size_response++;
        buf_r[size_response] = '\0';
    }
    debug_response(id_request, buf_r, size_response);
    close(fd);
    return size_response;
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
    debug_info("Unhandle sig: %s\n", sys_siglist[sig]);
}

void handler_default_on()
{
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

void handler_default_off()
{
    for (int s = 1; s <= 62; s++) {
        if (!is_handled(s)) {
            signal(s, SIG_DFL);
        }
    }
}

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
    debug("Connection Signals OFF | ");
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
    debug("Server Signals OFF | ");
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
    debug("Signals Fuzzer OFF | ");
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
                debug("Child %d exit OK, raising SIGINT to this process\n",
                      chld);
                raise(SIGINT);
                return;
            }

            debug("Raising child signal to this process\n");
            raise(signal_chld);
            return;
        } else {
            debug("Sending/Raising signal to everyone\n");
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
            debug("Queueing %s to %d because SIGUSR2", sys_siglist[SIGINT],
                  connection_pid);
            sigqueue(connection_pid, SIGINT, sv);
        }

        debug("Queueing %s to %d because SIGUSR2", sys_siglist[sig],
              sys_siglist[SIGINT], getpid());
        sigqueue(getpid(), SIGINT, sv); // TODO podrian ser equivalentes

        debug("Queueing %s to %d because SIGUSR2", sys_siglist[sig],
              sys_siglist[SIGINT], server_pid);

        sigqueue(server_pid, SIGUSR2, sv); // TODO podrian ser equivalentes
    }

    debug(" | End\n");
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
                debug("Child %d exit OK, raising SIGCONT to this process\n",
                      chld);
                raise(SIGCONT);
                return;
            }

            debug("Raising SIG signal to this process");
            debug("... & Closing logs\n ");
            close_all_log();
            raise(signal_chld);
            return;
        } else {
            debug("Sending/Raising signal to everyone\n");
            if (connection_pid != -1)
                kill(connection_pid, sig);
            kill(server_pid, sig);
            close_all_log();
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
            debug("Queueing %s to %d because SIGUSR2", sys_siglist[SIGINT],
                  connection_pid);
            sigqueue(connection_pid, SIGINT, sv);
        }

        debug("Queueing %s to %d because SIGUSR2", sys_siglist[sig],
              sys_siglist[SIGINT], getpid());
        sigqueue(getpid(), SIGINT, sv); // TODO podrian ser equivalentes

        debug("Queueing %s to %d because SIGUSR2", sys_siglist[sig],
              sys_siglist[SIGINT], server_pid);

        sigqueue(server_pid, SIGUSR2, sv); // TODO podrian ser equivalentes
    }

    debug(" | End\n");
}

void handle_sig_connection(int sig, siginfo_t *si, void *ucontext)
{
    debug_info("Fuzzer | Handling signal --%s-- (%d) | ", sys_siglist[sig],
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
                debug("Child %d exit OK, raising SIGINT to this process", chld);
                raise(SIGINT);
                return;
            }

            debug("Raising child signal to this process");
            raise(signal_chld);
            return;
        } else {
            debug("Sending/Raising signal to everyone");
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
            debug("Queueing %s to %d because SIGUSR2", sys_siglist[SIGINT],
                  connection_pid);
            sigqueue(connection_pid, SIGINT, sv);
        }

        debug("Queueing %s to %d because SIGUSR2", sys_siglist[sig],
              sys_siglist[SIGINT], getpid());
        sigqueue(getpid(), SIGINT, sv); // TODO podrian ser equivalentes

        debug("Queueing %s to %d because SIGUSR2", sys_siglist[sig],
              sys_siglist[SIGINT], server_pid);

        sigqueue(server_pid, SIGUSR2, sv); // TODO podrian ser equivalentes
    }

    debug("| End\n");
}

int main(int argc, char **argv)
{
    srand(time(NULL));

    open_log(LOG_DEBUG);
    open_log(LOG_REQUEST);
    open_log(LOG_RESPONSE);

    fuzzer_pid = getpid();
    handler_default_on();
    debug_info("Write something:\n");

    if ((server_pid = fork()) != 0) // PARENT: fuzzer
    {
        sleep(1); // waiting server UP

        handlers_on_fuzz();
        int loop = 0;
        while (__AFL_LOOP(10000)) {
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
                    debug_info("(loop:%d) Reading chunk...%d\n", loop,
                               chunk_size);
                    size_request += size_partial;
                } else if (size_partial < 0) {
                    if (errno != EINTR) {
                        buf[size_request + 1] = '\0';
                        debug_info("(loop:%d) STDIN ERROR (%s)\n", loop,
                                   strerror(errno));
                        die("Error reading request [read:%d, errno: %s]\n",
                            size_request, strerror(errno));
                    }
                } else {
                    buf[size_request + 1] = '\0';
                    debug_info("(loop:%d) REQUEST [size: %d]\n", loop,
                               size_request);
                    break;
                }
            }
            if (size_request + 5 < MAX_SIZE_REQUEST) {
                buf[size_request + 1] = '\r';
                buf[size_request + 2] = '\n';
                buf[size_request + 3] = '\r';
                buf[size_request + 4] = '\n';
                buf[size_request + 5] = '\0';
                size_request += 5;
            } else {
                debug_info("(loop:%d) MAX_SIZE_REQUEST\n", loop);
                buf[MAX_SIZE_REQUEST - 5] = '\r';
                buf[MAX_SIZE_REQUEST - 4] = '\n';
                buf[MAX_SIZE_REQUEST - 3] = '\r';
                buf[MAX_SIZE_REQUEST - 2] = '\n';
                buf[MAX_SIZE_REQUEST - 1] = '\0';
                size_request = MAX_SIZE_REQUEST;
            }

            debug_info("(loop:%d) sending... (size: %d)\n", loop, size_request);
            int s_r = send_request(buf, size_request);
            if (s_r < 0)
                debug_info("(loop:%d) sending error:%d\n", s_r);
        }

        debug_info("(loop:%d) | Final Loop\n", loop);
        kill(server_pid, SIGINT);
        close_all_log();
        return 0;
    } else // CHILD: HTTP SERVER
    {
        server_pid = getpid(); // remove
        handlers_on_server();
        int status = 0;
        if ((connection_pid = fork()) == 0) {
            connection_pid = getpid(); // remove
            if (execve("./httpd", NULL, NULL) < 0) {
                perror("error");
            }

        } else {
            handler_on_connection();

            while (1) {
                sleep(2);
                debug_info(
                    "Server-Fork | Sleeping & waiting to signal to be "
                    "handled\n");
            }
            debug_info("Server-Fork | everybody done\n");

            return 0;
        }
    }
    return 0;
}
