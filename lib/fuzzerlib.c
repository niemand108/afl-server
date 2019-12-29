#include "fuzzerlib.h"

void handler_on_connection()
{
    _debug_info("Connection Signals ON\n");

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
    _debug_info("Server Signals ON\n");

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
    _debug_info("Fuzzer Signals ON\n");

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
    _debug_info("Server | Handling signal --%s-- (%d) | ", sys_siglist[sig],
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
    _debug_info("Fuzzer | Handling signal --%s-- (%d) | ", sys_siglist[sig],
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
    _debug_info("CONN | Handling signal --%s-- (%d) | ", sys_siglist[sig],
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

inline void set_fuzz_server_pid(pid_t serv_pid)
{
    server_pid = serv_pid;
}

inline pid_t get_fuzz_server_pid()
{
    return server_pid;
}

inline void set_fuzz_conn_pid(pid_t conn_pid)
{
    connection_pid = conn_pid;
}

inline pid_t get_fucc_conn_pid()
{
    return connection_pid;
}

inline void set_fuzz_fuzzer_pid(pid_t fuzz_pid)
{
    fuzzer_pid = fuzz_pid;
}

inline pid_t get_fucc_fuzzer_pid()
{
    return fuzzer_pid;
}