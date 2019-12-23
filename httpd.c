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
#include <time.h>
#include <assert.h>

#define LOG_DEBUG_HTTPD "./logs/debug-httpd"
const int number_signals = 15;
int signals[number_signals] = {SIGINT, SIGHUP, SIGQUIT, SIGILL, SIGTRAP,
                               SIGABRT, SIGBUS, SIGFPE, SIGSEGV, SIGPIPE,
                               SIGTERM, SIGSTKFLT, SIGSTOP, SIGTSTP, SIGUSR2};

pid_t conn_pid = -1;
pid_t server_pid = -1;
//struct sigaction prevhandlers [number_signals];

void handle_sig(int, siginfo_t *, void *);
void handlers_on();
void handlers_off();
void handle_sig_default(int, siginfo_t *, void *); 
void handler_default_on();
void handler_default_off();
static void debug(const char *format, ...);


static void debug(const char *format, ...)
{
    pid_t actual_pid = getpid();
    va_list vargs;
    va_start(vargs, format);
    FILE *fptr;
    fptr = fopen(LOG_DEBUG_HTTPD, "a");
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    char t_s[64];
    assert(strftime(t_s, sizeof(t_s), "[%x %X]", tm));
    printf("%s [pid:%d] ", t_s, actual_pid);
    vprintf(format, vargs);
    printf("\n");
    va_end(vargs);
    va_start(vargs, format);
    fprintf(fptr, "%s [pid:%d] ", t_s, actual_pid);
    vfprintf(fptr, format, vargs);
    fprintf(fptr, ".\n");
    fclose(fptr);
    va_end(vargs);
}

void handlers_on()
{
    debug("Signals handlers ON for HTTPD process");
    struct sigaction new_action;
    new_action.sa_handler = handle_sig;
    sigemptyset (&new_action.sa_mask);
    new_action.sa_flags = SA_SIGINFO;

    for (int s = 0; s < number_signals; s++){
        //sigaction (signals[s], NULL, &(prevhandlers[s]));
        sigaction (signals[s], &new_action, NULL);
    }
}

void handlers_off(){
    debug("Signals handlers OFF for HTTPD process");
    for (int s = 0; s < number_signals; s++){
        signal(signals[s], SIG_DFL);
        //sigaction (signals[s], &(prevhandlers[s]), NULL);
    }
 }

void handle_sig(int sig, siginfo_t *si, void *ucontext)
{
    debug("Handler for --%s-- [pid: %d]", sys_siglist[sig], getpid());
    handlers_off();
    if (sig != SIGUSR2)
    {
        debug("(cont.) Signaling --signal:%s-- [to conn_pid:%d, server_pid:%d]", \
                sys_siglist[sig], conn_pid, server_pid); 
        if (conn_pid != -1)
            kill(conn_pid, sig);
        kill(server_pid, sig);
    }  
    else 
    {
        union sigval sv;
        
        if(si != NULL)
            sv.sival_int = si->si_value.sival_int;
        else
            sv.sival_int = 0xD1E;
        
        if(conn_pid != -1){
            debug("(cont.) Signaling --signal:%s-- [to connpid:%d]", sys_siglist[SIGINT], conn_pid);
            sigqueue(conn_pid, SIGINT, sv);
        }

        else
        {
            debug("(cont.) Signaling --signal:%s-- [to pid:%d]", sys_siglist[SIGINT]);
            sigqueue(getpid(), SIGINT, sv); //TODO podrian ser equivalentes
        }
        
        debug("(cont.) Signaling --signal:%s-- [to server_pid:%d]", sys_siglist[SIGUSR2], server_pid);
        sigqueue(server_pid, SIGUSR2, sv); //TODO podrian ser equivalentes
    }
    debug("(cont.) Ending handler for --%s--", sys_siglist[sig]);
}

void handle_sig_default(int sig, siginfo_t *si, void *ucontext){
    debug("Unhandle sig: %s", sys_siglist[sig]);
}

void handler_default_on(){
    debug("Signals default handlers ON for HTTPD process");
    for (int s = 1; s <= 62; s++){
        if(!is_handled(s))
        {
            if(sys_siglist[s] != NULL )
            {
                debug("Adding default handler to signal:%s", sys_siglist[s]);
            }
            else
            {
                debug("Adding default handler to signal:%d", s);
            }
            
            struct sigaction new_action;
            new_action.sa_handler = handle_sig_default;
            sigemptyset (&new_action.sa_mask);
            new_action.sa_flags = 0;
            sigaction (s, &new_action, NULL);
        }
    }
}

void handler_default_off(){
    debug("Signals default handlers OFF for HTTPD process");
    for (int s = 1; s <= 62; s++){
        if(!is_handled(s)){
            signal(s, SIG_DFL);
        }
    }
}

int is_handled(int sig)
{
    for (int s = 0; s < number_signals; s++)
        if(signals[s] == sig)
            return 1;
    return 0;
}


int main(int argc, char** argv) { //CONNECTION
    srand(time(NULL));
    char *args[] = {"socat", "tcp6-listen:80,reuseaddr,fork", "SYSTEM:\"/bin/echo hola\"", NULL};
    server_pid = getpid();
    handlers_on();
    handler_default_on();
    if ((conn_pid = fork()) == 0)
    { 
        execvp("/usr/bin/socat", args);
    }
    else //SELECT
    {
        int status = 0;
        do {
            debug("waitpid pid:%d", conn_pid);
            int w = waitpid(conn_pid, &status, WUNTRACED | WCONTINUED);
            if (w == -1)
            {
                perror("waitpid");
                exit(EXIT_FAILURE);
            }

            if (WIFEXITED(status)) {
                    debug("[pid: %d exited] status=%d", conn_pid, WEXITSTATUS(status));
                } else if (WIFSIGNALED(status)) {
                    debug("[pid: %d killed by signal %s]", conn_pid, sys_siglist[WTERMSIG(status)]);
                    debug("Signaling to %d with signal %s", server_pid, sys_siglist[WTERMSIG(status)]);
                    kill(server_pid, WTERMSIG(status));
                }
                else if (WIFSTOPPED(status))
                {
                    debug("[pid: %d stopped by signal %s]", conn_pid, sys_siglist[WSTOPSIG(status)]);
                    debug("Signaling to %d with signal %s", server_pid, sys_siglist[WSTOPSIG(status)]);
                    kill(server_pid, WSTOPSIG(status));
                }
                else if (WIFCONTINUED(status))
                {
                    debug("[pid: %d continued (sig c.)]", conn_pid);
                }
            debug("while waitpid");
            } while (!WIFEXITED(status) && !WIFSIGNALED(status));
            
            debug("ending waitpid");
    }
            return 0;
}
