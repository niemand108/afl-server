#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/wait.h>

pid_t fuzzer_pid=-1, server_pid=-1;
const int number_signals = 13;
int signals[number_signals] = {SIGHUP, SIGQUIT, SIGILL, SIGTRAP,
                               SIGABRT, SIGBUS, SIGFPE, SIGSEGV, SIGPIPE,
                               SIGTERM, SIGSTKFLT, SIGSTOP, SIGTSTP};

struct sigaction prevhandlers_fuzz[number_signals];
struct sigaction prevhandlers_server[number_signals];
struct sigaction prevhandler_conn;

void handle_sig_fuzz(int);
void handlers_on_fuzz();
void handlers_off_fuzz();
void handle_sig_server(int);
void handlers_on_server();
void handlers_off_server();
void send_signal_fuzz(int);
void send_signal_server(int);
void handler_connection_on();
void handler_connection_off();
void handle_sig_connection(int);

int is_handled(int sig)
{
    for (int s = 0; s < number_signals; s++)
        if(signals[s] == sig)
            return 1;
    return 0;
}

void handler_on_connection(){
    struct sigaction new_action;
    new_action.sa_handler = handle_sig_connection;
    sigemptyset (&new_action.sa_mask);
    new_action.sa_flags = 0;
    sigaction (SIGCHLD, NULL, &prevhandler_conn);
    sigaction (SIGCHLD, &new_action, NULL);
}

void handler_off_connection(){
    sigaction (SIGCHLD, &prevhandler_conn, NULL);
    printf("Signals handlers connections OFF\n");
}

void handlers_on_server()
{
    struct sigaction new_action;
    new_action.sa_handler = handle_sig_server;
    sigemptyset (&new_action.sa_mask);
    new_action.sa_flags = 0;

    for (int s = 0; s < number_signals; s++){
        sigaction (signals[s], NULL, &(prevhandlers_server[s]));
        sigaction (signals[s], &new_action, NULL);
    }
}

void handlers_off_server(){
    for (int s = 0; s < number_signals; s++){
        sigaction (signals[s], &(prevhandlers_server[s]), NULL);
    }
    printf("Signals handlers server OFF\n");
    fflush(stdout);
}

void handlers_on_fuzz()
{
    struct sigaction new_action;
    new_action.sa_handler = handle_sig_fuzz;
    sigemptyset (&new_action.sa_mask);
    new_action.sa_flags = 0;

    for (int s = 0; s < number_signals; s++){
        sigaction (signals[s], NULL, &(prevhandlers_fuzz[s]));
        sigaction (signals[s], &new_action, NULL);
    }
}

void handlers_off_fuzz(){
    for (int s = 0; s < number_signals; s++){
        sigaction (signals[s], &(prevhandlers_fuzz[s]), NULL);
    }
    printf("Signals handlers fuzz OFF\n");
    fflush(stdout);
}

void handle_sig_server(int sig){
    printf("Server signal received: %d, pid: %d\n", sig, getpid());
    handlers_off_server();
    //handle_sig_fuzz(sig);
    //kill(getppid(), sig);
    kill(server_pid, sig);
}

void handle_sig_fuzz(int sig){
    printf("Fuzz signal received: %d, pid: %d\n", sig, getpid());
    handlers_off_fuzz();
    //kill(getppid(), sig);
    kill(fuzzer_pid, sig);
}

void handle_sig_connection(int sig){
    pid_t pid_conn;
    int status;
    printf("Connection signal received: %d\n", sig);
    while ((pid_conn = waitpid(-1, &status, WNOHANG)) != -1){
        send_signal_server(WTERMSIG(status));
    }
}

void send_signal_server(int s){
    //sending before, otherwise could be later
    send_signal_fuzz(s);
    if (server_pid > 0)
        kill(server_pid, s);
    else
    {
        printf("Sending signal to server but unknown server_pid\n");
    }
}

void send_signal_fuzz(int s){
    if (fuzzer_pid > 0){
        kill(fuzzer_pid, s);
    }
    else
    {
        printf("Sending signal to fuzz but unknown fuzzer_pid\n");
    }
}

int main(int argc, char** argv) {
    
    fuzzer_pid = getpid();
    
    printf("Write somethings:\n");
    if (fork() != 0)  //PARENT: fuzzer
    {
        handlers_on_fuzz();
        char buf[128]; 
        ssize_t read_bytes;
        FILE *fptr;
        fptr = fopen("./fork.fuzzer.txt", "a");
        while (__AFL_LOOP(1000))
        {
            read_bytes = -1;
            memset(buf, 0, 128);
            while ((read_bytes = read(0, buf, 128)) > 0)
            {
                printf("fuzzer read %d bytes\n", read_bytes);
                fprintf(fptr, "Reading stdin, size: %d, pid: %d\n", read_bytes, getpid());
                break;
            }
        }
        printf("Bye parent from fuzzer.\n");
        sleep(10);
        fclose(fptr);
        exit(0);
    }
    else // CHILD: HTTP SERVER
    {
        server_pid = getpid();
        sleep(1);
        int status = 0;
        handlers_on_server();
        handler_on_connection();
        if (fork() == 0) //CONNECTION
        {
            sleep(1);
            if (execve("./httpd", NULL, NULL) < 0)
            {
                perror("error");
            } else {
                printf("executed ./sigsev\n");
            }
            printf("bye child execve\n");
            fflush(stdout);
        }
        else
        {
            //while( wait(&status) > 0);
            while(sleep(1) == 0);
        }
        printf("Bye child from server.\n");
    }
        
return 0;
}
