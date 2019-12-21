#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <signal.h>

const int number_signals = 13;
int signals[number_signals] = {SIGHUP, SIGQUIT, SIGILL, SIGTRAP,
                               SIGABRT, SIGBUS, SIGFPE, SIGSEGV, SIGPIPE,
                               SIGTERM, SIGSTKFLT, SIGSTOP, SIGTSTP};

pid_t child_pid;
pid_t parent_pid;
struct sigaction prevhandlers [number_signals];

void handle_sig(int);
void handlers_on();
void handlers_off();

void handlers_on()
{
    struct sigaction new_action;
    new_action.sa_handler = handle_sig;
    sigemptyset (&new_action.sa_mask);
    new_action.sa_flags = 0;

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

void handle_sig(int sig)
{
    printf("Sigsev signal received: %d, pid: %d\n", sig, getpid());
    handlers_off();
    kill(getpid(), sig);
}

int main(int argc, char** argv) { //CONNECTION
    int status = 0;
    if ((child_pid = fork()) == 0)
    { 
        handlers_on();
        while (1)
        {
            sleep(1);
            printf("Still here... (%d)\n", child_pid);
        }
    }
    else //SELECT
    {

        while((parent_pid = wait(&status)) > 0);
        printf("child exit -> received signal (%d)\nBye from sigsev.\n", WTERMSIG(status));
    }

return 0;
}
