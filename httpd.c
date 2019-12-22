#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netdb.h>

#define LOG_DEBUG_HTTPD "./logs/debug-httpd"
const int number_signals = 15;
int signals[number_signals] = {SIGINT, SIGHUP, SIGQUIT, SIGILL, SIGTRAP,
                               SIGABRT, SIGBUS, SIGFPE, SIGSEGV, SIGPIPE,
                               SIGTERM, SIGSTKFLT, SIGSTOP, SIGTSTP, SIGUSR2};

pid_t conn_pid;
pid_t server_pid;
struct sigaction prevhandlers [number_signals];

void handle_sig(int, siginfo_t *, void *);
void handlers_on();
void handlers_off();
static void die(int line_number, const char *format, ...);
static void debug(const char *format, ...);

static void debug(const char *format, ...)
{
	va_list vargs;
	va_start(vargs, format);
    FILE *fptr;
    fptr = fopen(LOG_DEBUG_HTTPD, "a");
	vfprintf(fptr, format, vargs);
	fprintf(fptr, ".\n");
    fclose(fptr);
    va_end(vargs);
}

void handlers_on()
{
    struct sigaction new_action;
    new_action.sa_handler = handle_sig;
    sigemptyset (&new_action.sa_mask);
    new_action.sa_flags = SA_SIGINFO;

    for (int s = 0; s < number_signals; s++){
        sigaction (signals[s], NULL, &(prevhandlers[s]));
        sigaction (signals[s], &new_action, NULL);
    }
}

void handlers_off(){
    for (int s = 0; s < number_signals; s++){
        sigaction (signals[s], &(prevhandlers[s]), NULL);
    }
 }

void handle_sig(int sig, siginfo_t *si, void *ucontext)
{
    handlers_off();
    if (sig != SIGUSR2)
    {
        debug("killing connection & server\n");
        fflush(stdout);
        if(conn_pid != -1)
            kill(conn_pid, sig);
        kill(server_pid, sig);
    }  
    else 
    {
        debug("Signal SIGUSR2 received: %d, pid: %d\n", sig, getpid());
        fflush(stdout);
        
        union sigval sv;
        
        if(si != NULL)
            sv.sival_int = si->si_value.sival_int;
        else
            sv.sival_int = 0xD1E;
        
        if(conn_pid != -1)
            sigqueue(conn_pid, SIGABRT, sv);

        else
        {
            sigqueue(getpid(), SIGABRT, sv); //TODO podrian ser equivalentes
        }
        
        sigqueue(server_pid, SIGABRT, sv); //TODO podrian ser equivalentes
    }
}

static void die(int line_number, const char *format, ...)
{
	va_list vargs;
	va_start(vargs, format);
	fprintf(stderr, "DIE: %d: ", line_number);
	vfprintf(stderr, format, vargs);
	fprintf(stderr, ".\n");
	va_end(vargs);
    kill(SIGUSR2, getpid());
    exit(1);
}

int main(int argc, char** argv) { //CONNECTION
    char *args[] = {"socat", "tcp6-listen:80,reuseaddr,fork", "SYSTEM:\"/bin/echo hola\"", NULL};
    server_pid = getpid();
    handlers_on();
    if ((conn_pid = fork()) == 0)
    { 
        int e = execvp("/usr/bin/socat", args);
        //system("socat tcp6-listen:80,reuseaddr,fork SYSTEM:\"/bin/echo hola\"");
        //handlers_on();
        //printf("execve %d\n", e);
        //perror("scfdarf");
        fflush(stdout);
        //sleep(1);
        return 0;
        
        debug("Still here... (%d)\n", conn_pid);

    }
    else //SELECT
    {
        int status = 0;
        do {
                int w = waitpid(conn_pid, &status, WUNTRACED | WCONTINUED);
                if (w == -1) {
                    perror("waitpid");
                    exit(EXIT_FAILURE);
                }

            if (WIFEXITED(status)) {
                    debug("exited, status=%d\n", WEXITSTATUS(status));
                } else if (WIFSIGNALED(status)) {
                    debug("killed by signal %d\n", WTERMSIG(status));
                    kill(server_pid, WTERMSIG(status));
                }
                else if (WIFSTOPPED(status))
                {
                    debug("stopped by signal %d\n", WSTOPSIG(status));
                    kill(server_pid, WSTOPSIG(status));
                }
                else if (WIFCONTINUED(status))
                {
                    printf("continued\n");
                }
            } while (!WIFEXITED(status) && !WIFSIGNALED(status));
        }


return 0;
}
