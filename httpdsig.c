#include "httpdsig.h"
#include "util.h"

void set_server_pid(pid_t pid)
{
    server_pid_httpdlib = pid;
}
pid_t get_server_pid()
{
    return server_pid_httpdlib;
}

void set_conn_pid(pid_t pid)
{
    conn_pid_httpdlib = pid;
}
pid_t get_conn_pid()
{
    return conn_pid_httpdlib;
}

void debug_httpd(const char *format, ...)
{
    return; //TODO
    va_list vargs;
    va_start(vargs, format);
    va_end(vargs);
}

void handlers_httpd_on()
{
    debug_info("HTTPD Signals ON\n");
    struct sigaction new_action;
    new_action.sa_handler = handle_sig;
    sigemptyset(&new_action.sa_mask);
    new_action.sa_flags = SA_SIGINFO;

    for (int s = 0; s < number_signals; s++) {
        sigaction(signals[s], &new_action, NULL);
    }
}

void handlers_httpd_off()
{
    _debug("Signals OFF | ");
    for (int s = 0; s < number_signals; s++) {
        signal(signals[s], SIG_DFL);
    }
}

void handle_sig(int sig, siginfo_t *si, void *ucontext)
{
    debug_info("HTTPD | Handling signal --%s-- (%d) | ",
               sys_siglist[sig], getpid());

    handlers_httpd_off();

    if (sig == SIGCHLD) {
        pid_t chld;
        int status;

        while ((chld = waitpid(WAIT_ANY, &status, WUNTRACED | WNOHANG)) != -1)
            ;

        int signal_child = why_child_exited(chld, status);
        if (signal_child == 0) {
            debug_info("Child exit OK, raising SIGCONT to this process(HTTPD)");
            handlers_httpd_on();
            _debug("\n");
            //raise(SIGCONT);
            return;
        }
        handlers_httpd_on();
        _debug("Raising child signal %d to this process(HTTPD)\n", signal_child);
        raise(signal_child);
    } else if (sig != SIGUSR2) {
        _debug("Sending signal %s to con: %d, serv:%d",
               sys_siglist[sig], conn_pid_httpdlib, server_pid_httpdlib);
        kill(server_pid_httpdlib, sig);
        if (conn_pid_httpdlib != -1 && getpid() != conn_pid_httpdlib)
            kill(conn_pid_httpdlib, sig);
    } else if (sig == SIGUSR2) {
        union sigval sv;

        if (si != NULL)
            sv.sival_int = si->si_value.sival_int;
        else
            sv.sival_int = 0xD1E;

        if (conn_pid_httpdlib != -1) {
            _debug("Queueing %s to %d because SIGUSR2",
                   sys_siglist[SIGINT], conn_pid_httpdlib);
            sigqueue(conn_pid_httpdlib, SIGINT, sv);
        }

        _debug("Queueing %s to %d because SIGUSR2",
               sys_siglist[SIGINT], getpid());
        sigqueue(getpid(), SIGINT, sv); //TODO podrian ser equivalentes

        _debug("Queueing %s to %d because SIGUSR2",
               sys_siglist[SIGINT], server_pid_httpdlib);

        sigqueue(server_pid_httpdlib, SIGUSR2, sv); //TODO podrian ser equivalentes
    }
    _debug(" | End\n");
}
