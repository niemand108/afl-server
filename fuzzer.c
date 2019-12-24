#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/wait.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netdb.h>
#include <time.h>
#include <assert.h>
#include "util.c"

#define MAX_SIZE_REQUEST 200000
#define MAX_SIZE_RESPONSE 200000
#define HOSTNAME_HTTPD  0 /* localhost */
#define PORTNAME_HTTPD "http"
#define LOG_RESPONSE "./logs/response"
#define LOG_REQUEST "./logs/request"

pid_t fuzzer_pid=-1, server_pid=-1, connection_pid = -1;


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
static void debug_response(int, char *, int);
static void debug_request(int, char *, int);

static void debug_request(int id_request, char* request, int size_request)
{
    char log[200];
    snprintf(log, 200, "\nREQUEST id=%d, size=%d\n", id_request, size_request);
    debug_to(LOG_REQUEST, log);
    debug_to(LOG_REQUEST, request);
}

static void debug_response(int id_request, char * response, int size_response)
{
    char log[200];
    snprintf(log, 200, "RESPONSE id=%d, size=%d\n", id_request, size_response);
    debug_to(LOG_RESPONSE, log);
    debug_to(LOG_RESPONSE, response);
}


int send_request(char *request, size_t size_request){				
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
    if (err != 0){
        die("(id_req: %d) Failed to resolve remote socket address (err=%d)", id_request, err);
    } 

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd == -1){
        die("(id_req: %d) Socket: %s name: %s port:%d", id_request, strerror(errno), res->ai_canonname, portname);
    }

    debug("(id_req: %d) Conectando...", id_request);
    if (connect(fd, res->ai_addr, res->ai_addrlen) == -1)
    {
        die("(id_req: %d) Socket connect: %s", id_request, strerror(errno));
    }

    int written;
    if ((written = write(fd, request, size_request)) == -1){
        debug("(id_req: %d) write socket:  %s", id_request, strerror(errno));
        return -EAGAIN;
    }
    assert(written == size_request);

    debug("(id_req: %d) HTTP REQUEST DONE [written:%d size_request:%d]", id_request, written, size_request);
    debug_request(id_request, request, size_request);

    freeaddrinfo(res);

    ssize_t size_response = 0, size_partial;
    int chunk_size = 1000;
    int max_resp_reads = MAX_SIZE_RESPONSE / chunk_size;
    char buf_r[MAX_SIZE_RESPONSE+1];
    memset(buf_r, 0, MAX_SIZE_RESPONSE+1);

    debug("(id_req: %d) Reading response...", id_request);
    //TODO: timeout read
    for (;;)
    {
        if (max_resp_reads <= 0){
            break;
        }
        size_partial = read(fd, buf_r+size_response, chunk_size);
        if(size_partial > 0){           
            max_resp_reads--;
            size_response += size_partial;
        }
        else if (size_partial < 0){
            if (errno != EINTR){
                debug("(id_req: %d) Partial response [size: %d]\n%s\n(EOF) ", id_request, size_response, buf_r);
                die("(id_req: %d) Error reading response [read:%d, errno: %s]", id_request, size_response, strerror(errno));
            }
        } else {
            //printf("->>> %d, %d\n", size_response, strlen(buf_r));
            //fflush(stdout);
            debug("(id_req: %d) HTTP RESPONSE [size: %d])", id_request, size_response);
            break;
        }
    }
    assert(size_request < MAX_SIZE_RESPONSE);
    if(buf_r[size_response] != '\0' ){
        size_response++;
        buf_r[size_response] = '\0';
    }
    debug_response(id_request, buf_r, size_response);
    debug("(id_req: %d) ending (read) response & return 0", id_request);
    close(fd);
    return size_response ;

}

int is_handled(int sig)
{
    for (int s = 0; s < number_signals; s++)
        if(signals[s] == sig)
            return 1;
    return 0;
}

void handle_sig_default(int sig, siginfo_t *si, void *ucontext){
    debug("Unhandle sig: %s", sys_siglist[sig]);
}

void handler_default_on(){
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

void handler_default_off(){
    for (int s = 1; s <= 62; s++){
        if(!is_handled(s)){
            signal(s, SIG_DFL);
        }
    }
}


void handler_on_connection()
{
    debug("Connection | Signals ON");
    
    for (int s = 1; s <= 62; s++)
    {
        if(is_handled(s))
        {
            struct sigaction new_action;
            new_action.sa_handler = handle_sig_connection;
            sigemptyset (&new_action.sa_mask);
            new_action.sa_flags = 0;
            sigaction (s, &new_action, NULL);
        }
    }
}

void handler_off_connection()
{
    debug("Connection | Signals OFF");
    for (int s = 1; s <= 62; s++)
    {
        if(is_handled(s))
        {
            signal(s, SIG_DFL);
        }
    }
}

void handlers_on_server()
{
    debug("Server | Signals ON");

    struct sigaction new_action;
    new_action.sa_handler = handle_sig_server;
    sigemptyset (&new_action.sa_mask);
    new_action.sa_flags = 0;

    for (int s = 0; s < number_signals; s++)
    {
        sigaction (signals[s], &new_action, NULL);
    }
}

void handlers_off_server()
{
    debug("Server | Signals OFF");
    for (int s = 0; s < number_signals; s++)
    {
        signal(signals[s], SIG_DFL);
    }    
}

void handlers_on_fuzz()
{
    debug("Fuzzer | Signals ON");

    struct sigaction new_action;
    new_action.sa_handler = handle_sig_fuzz;
    sigemptyset (&new_action.sa_mask);
    new_action.sa_flags = 0;

    for (int s = 0; s < number_signals; s++)
    {
        sigaction (signals[s], &new_action, NULL);
    }
}

void handlers_off_fuzz()
{
    debug("Fuzzer | Signals OFF");
    for (int s = 0; s < number_signals; s++)
    {
        signal(signals[s], SIG_DFL);
    }
}


void handle_sig_server(int sig, siginfo_t *si, void *ucontext){
    char header_log[200];
    snprintf(header_log, 200, "Server | Handling signal | --%s-- (%d) |", \
                                sys_siglist[sig], getpid());
    debug(header_log);
    handlers_off_server();
    if (sig!= SIGUSR2)
    {
        if(sig ==SIGCHLD)
        {
            pid_t chld;
            int status;
            while ((chld = waitpid(-1, &status, WUNTRACED | WNOHANG)) != -1)
                ;

            int signal_chld =  why_child_exited(chld, status, header_log);

            if(signal_chld == 0)
            {
                debug("%s Child %d exit OK", header_log, chld);
                return;
            }

            debug("%s Raising child signal to this process", header_log );
            raise(signal_chld);
            return;
        }
        else
        {
            debug("%s Sending/Raising signal to everyone", header_log);
            if(connection_pid != -1)
                kill(connection_pid, sig);
            kill(fuzzer_pid, sig);
            raise(sig);
            return;
        }
    }  
    else 
    {
        union sigval sv;
        
        if(si != NULL)
            sv.sival_int = si->si_value.sival_int;
        else
            sv.sival_int = 0xD1E;
        
       if(connection_pid != -1){
            debug("%s Queueing %s to %d because SIGUSR2", \
                header_log, sys_siglist[SIGINT], connection_pid);
            sigqueue(connection_pid, SIGINT, sv);
        }

        debug("%s Queueing %s to %d because SIGUSR2", header_log,\
                sys_siglist[sig], sys_siglist[SIGINT], getpid());
        sigqueue(getpid(), SIGINT, sv); //TODO podrian ser equivalentes
  
        
        debug("%s Queueing %s to %d because SIGUSR2", header_log,\
                sys_siglist[sig], sys_siglist[SIGINT], server_pid);

        sigqueue(server_pid, SIGUSR2, sv); //TODO podrian ser equivalentes
    }

    debug("%s | End", header_log);
}

void handle_sig_fuzz(int sig, siginfo_t *si, void *ucontext){
    char header_log[200];
    snprintf(header_log, 200, "Fuzzer | Handling signal | --%s-- (%d) |", \
                                sys_siglist[sig], getpid());
    debug(header_log);
    handlers_off_fuzz();

    if (sig != SIGUSR2)
    {
        if(sig ==SIGCHLD)
        {
            pid_t chld;
            int status;
            while ((chld = waitpid(-1, &status, WUNTRACED | WNOHANG)) != -1)
                ;

            int signal_chld =  why_child_exited(chld, status, header_log);

            if(signal_chld == 0)
            {
                debug("%s Child %d exit OK", header_log, chld);
                return;
            }

            debug("%s Raising child signal to this process", header_log );
            raise(signal_chld);
            return;
        }
        else
        {
            debug("%s Sending/Raising signal to everyone", header_log);
            if(connection_pid != -1)
                kill(connection_pid, sig);
            kill(server_pid, sig);
            raise(sig);
            return;
        }
    }  
    else 
    {
        union sigval sv;
        
        if(si != NULL)
            sv.sival_int = si->si_value.sival_int;
        else
            sv.sival_int = 0xD1E;
        
       if(connection_pid != -1){
            debug("%s Queueing %s to %d because SIGUSR2", \
                header_log, sys_siglist[SIGINT], connection_pid);
            sigqueue(connection_pid, SIGINT, sv);
        }

        debug("%s Queueing %s to %d because SIGUSR2", header_log,\
                sys_siglist[sig], sys_siglist[SIGINT], getpid());
        sigqueue(getpid(), SIGINT, sv); //TODO podrian ser equivalentes
  
        
        debug("%s Queueing %s to %d because SIGUSR2", header_log,\
                sys_siglist[sig], sys_siglist[SIGINT], server_pid);

        sigqueue(server_pid, SIGUSR2, sv); //TODO podrian ser equivalentes
    }

    debug("%s | End", header_log);
}

void handle_sig_connection(int sig, siginfo_t *si, void *ucontext){
    char header_log[200];
    snprintf(header_log, 200, "Fuzzer | Handling signal | --%s-- (%d) |", \
                                sys_siglist[sig], getpid());
    debug(header_log);
    handlers_off_fuzz();

    if (sig != SIGUSR2)
    {
        if(sig ==SIGCHLD)
        {
            pid_t chld;
            int status;
            while ((chld = waitpid(-1, &status, WUNTRACED | WNOHANG)) != -1)
                ;

            int signal_chld =  why_child_exited(chld, status, header_log);

            if(signal_chld == 0)
            {
                debug("%s Child %d exit OK", header_log, chld);
                return;
            }

            debug("%s Raising child signal to this process", header_log );
            raise(signal_chld);
            return;
        }
        else
        {
            debug("%s Sending/Raising signal to everyone", header_log);
            if(connection_pid != -1)
                kill(connection_pid, sig);
            kill(server_pid, sig);
            raise(sig);
            return;
        }
    }  
    else 
    {   
        union sigval sv;
        
        if(si != NULL)
            sv.sival_int = si->si_value.sival_int;
        else
            sv.sival_int = 0xD1E;
        
       if(connection_pid != -1){
            debug("%s Queueing %s to %d because SIGUSR2", \
                header_log, sys_siglist[SIGINT], connection_pid);
            sigqueue(connection_pid, SIGINT, sv);
        }

        debug("%s Queueing %s to %d because SIGUSR2", header_log,\
                sys_siglist[sig], sys_siglist[SIGINT], getpid());
        sigqueue(getpid(), SIGINT, sv); //TODO podrian ser equivalentes
  
        
        debug("%s Queueing %s to %d because SIGUSR2", header_log, \
                sys_siglist[sig], sys_siglist[SIGINT], server_pid);

        sigqueue(server_pid, SIGUSR2, sv); //TODO podrian ser equivalentes
    }

    debug("%s | End", header_log);
}

int main(int argc, char **argv)
{
    srand(time(NULL));

    fuzzer_pid = getpid();
    handler_default_on();       
    debug("Write something:");

    if ((server_pid = fork()) != 0) //PARENT: fuzzer
    {
        sleep(1); //waiting server UP

        handlers_on_fuzz();
        int loop = 0;
        while (__AFL_LOOP(10000))
        {
            loop++;
            char buf[MAX_SIZE_REQUEST + 1];
            const int chunk_size = 1000;
            int max_reads = MAX_SIZE_REQUEST / chunk_size;
            ssize_t size_request = 0, size_partial;
            memset(buf, 0, MAX_SIZE_REQUEST);

            debug("(loop:%d) Reading stdin...", loop);
            for (;;)
            {
                if (max_reads <= 0)
                    break;
                max_reads--;
                size_partial = read(0, buf + size_request, chunk_size);
                if (size_partial > 0)
                {
                    debug("(loop:%d) Reading chunk...%d", loop, chunk_size);
                    size_request += size_partial;
                }
                else if (size_partial < 0)
                {
                    if (errno != EINTR)
                    {
                        buf[size_request + 1] = '\0';
                        debug("(loop:%d) STDIN ERROR (%s)", loop, strerror(errno));
                        die("Error reading request [read:%d, errno: %s]", size_request, strerror(errno));
                    }
                }
                else
                {
                    buf[size_request + 1] = '\0';
                    debug( "(loop:%d) REQUEST [size: %d]", loop, size_request);
                    break;
                }
            }
            if (size_request + 5 < MAX_SIZE_REQUEST)
            {
                buf[size_request + 1] = '\r';
                buf[size_request + 2] = '\n';
                buf[size_request + 3] = '\r';
                buf[size_request + 4] = '\n';
                buf[size_request + 5] = '\0';
                size_request += 5;
            }
            else
            {
                debug("(loop:%d) MAX_SIZE_REQUEST", loop);
                buf[MAX_SIZE_REQUEST - 5] = '\r';
                buf[MAX_SIZE_REQUEST - 4] = '\n';
                buf[MAX_SIZE_REQUEST - 3] = '\r';
                buf[MAX_SIZE_REQUEST - 2] = '\n';
                buf[MAX_SIZE_REQUEST - 1] = '\0';
                size_request = MAX_SIZE_REQUEST;
            }

            debug("(loop:%d) sending... (size: %d)", loop, size_request);
            int s_r = send_request(buf, size_request);
            if (s_r < 0)
                debug("(loop:%d) sending error:%d", s_r);
        }
        
        debug("(loop:%d) | End");
        kill(server_pid, SIGINT);
        return 0;
    }
    else // CHILD: HTTP SERVER
    {
        server_pid = getpid(); //remove
        handlers_on_server();
        int status = 0;
        if ((connection_pid = fork()) == 0) //CONNECTION
        {
            connection_pid = getpid(); //remove
            if (execve("./httpd", NULL, NULL) < 0)
            {
                perror("error");
            }
            
        }
        else
        {
            handler_on_connection();

            pid_t pid_conn;
            int status;
            while ((pid_conn = waitpid(-1, &status, WUNTRACED | WNOHANG)) != -1);

            int signal_child = why_child_exited(pid_conn, status, "Server-FORK | ");

            if(signal_child == 0 ){
                debug("Server-Fork | child(httpd) exited OK");
                return 0;
            }

            raise(signal_child);

            debug("Server-Fork | everybody done");
            while(1){
                sleep(2);
                debug("Server-Fork | Sleeping & waiting to signal to be handled");
            }
            //kill(server_pid, SIGUSR2);
            //kill(fuzzer_pid, SIGUSR2);
            return 0;
        }
    }
    return 0;
}
