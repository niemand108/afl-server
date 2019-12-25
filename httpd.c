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
#include "util.c"

#define LOG_DEBUG_HTTPD "./logs/debug-httpd"


pid_t conn_pid = -1;
pid_t server_pid = -1;

void handle_sig(int, siginfo_t *, void *);
void handlers_httpd_on();
void handlers_httpd_off();
void handle_sig_default(int, siginfo_t *, void *); 
void handler_others_on();
void handler_others_off();
static void debug_httpd(const char *, ...);

static void debug_httpd(const char *format, ...)
{
    return;  //TODO
    va_list vargs;
    va_start(vargs, format);
    //char log[200];
    //vsnprintf(log, 200, format, vargs);
    //debug_to(LOG_DEBUG_HTTPD, format, vargs);
    va_end(vargs);
}

void handlers_httpd_on()
{
    debug_info("HTTPD Signals ON\n");
    struct sigaction new_action;
    new_action.sa_handler = handle_sig;
    sigemptyset (&new_action.sa_mask);
    new_action.sa_flags = SA_SIGINFO;

    for (int s = 0; s < number_signals; s++){
        sigaction (signals[s], &new_action, NULL);
    }
}

void handlers_httpd_off(){
    debug("Signals OFF | ");
    for (int s = 0; s < number_signals; s++){
        signal(signals[s], SIG_DFL);
    }
 }

void handle_sig(int sig, siginfo_t *si, void *ucontext)
{
    debug_info("HTTPD | Handling signal --%s-- (%d) | ", \
                                sys_siglist[sig], getpid());

    handlers_httpd_off();

    if (sig == SIGCHLD)
    {
        pid_t chld;
        int status;

        while ((chld = waitpid(WAIT_ANY, &status, WUNTRACED | WNOHANG)) != -1)
            ;

        int signal_child = why_child_exited(chld, status);
        if (signal_child == 0)
        {
            debug_info("Child exit OK, raising SIGINT to this process");
            raise(SIGINT);
            return;
        }

        debug("Raising child signal to this process");
        raise(signal_child);
    } 
    else if (sig != SIGUSR2)
    {
        debug("Sending signal %s to %d, %d",\
                 sys_siglist[sig],  conn_pid, server_pid);
        if (conn_pid != -1 && getpid() != conn_pid)
            kill(conn_pid, sig);
        kill(server_pid, sig);
    }  
    else if( sig == SIGUSR2)
    {        union sigval sv;
        
        if(si != NULL)
            sv.sival_int = si->si_value.sival_int;
        else
            sv.sival_int = 0xD1E;
        
        if(conn_pid != -1){
            debug("Queueing %s to %d because SIGUSR2", \
                sys_siglist[SIGINT], conn_pid);
            sigqueue(conn_pid, SIGINT, sv);
        }

        debug("Queueing %s to %d because SIGUSR2", \
                sys_siglist[SIGINT], getpid());
        sigqueue(getpid(), SIGINT, sv); //TODO podrian ser equivalentes
  
        
        debug("Queueing %s to %d because SIGUSR2", \
                sys_siglist[SIGINT], server_pid);

        sigqueue(server_pid, SIGUSR2, sv); //TODO podrian ser equivalentes
    }
    debug(" | End\n");
}

void handle_sig_default(int sig, siginfo_t *si, void *ucontext)
{
    debug_info("HTTPD | Unhandle %s\n", sys_siglist[sig]);
}

void handler_others_on()
{
    debug_info("HTTPD | Other signals ON\n");
    for (int s = 1; s <= 62; s++){
        if(!is_handled(s))
        {            
            struct sigaction new_action;
            new_action.sa_handler = handle_sig_default;
            sigemptyset (&new_action.sa_mask);
            new_action.sa_flags = 0;
            sigaction (s, &new_action, NULL);
        }
    }
}

void handler_others_off()
{
    debug_info("HTTPD | Other signals OFF\n");
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


int main(int argc, char** argv) {
    srand(time(NULL));
    server_pid = getpid();
    handlers_httpd_on();
    handler_others_on();

    if ((conn_pid = fork()) == 0)
    {   
        char *args[] = {"socat", "tcp6-listen:80,reuseaddr,fork", "SYSTEM:\"/bin/echo hola\"", NULL};
        execvp("/usr/bin/socat", args);
    }
    else //SELECT
    {
        /*
        pid_t pid_conn;
        int status;
        debug("HTTPD-PARENT | waiting child (socat)");
        do{                
                debug("whut");
        } 
        while ((pid_conn = waitpid(WAIT_ANY, &status, WUNTRACED| WNOHANG)) != -1);

        int signal_child = why_child_exited(pid_conn, status, "HTTPD-PARENT| ");
        if(signal_child == 0 ){
            debug("HTTPD-PARENT | child(socat) exited OK");
            return 0;
        }

        raise(signal_child);
*/
        debug_info("HTTPD-PARENT | everybody done\n");
        while(1){
            sleep(2);
            debug_info("HTTPD-PARENT | Sleeping & waiting to signal to be handled\n");
        }
    }
    return 0;
}
