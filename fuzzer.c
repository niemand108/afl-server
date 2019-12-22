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

#define MAX_SIZE_REQUEST 200000
#define MAX_SIZE_RESPONSE 200000
#define LOG_REQUESTS "./logs/requests"
#define LOG_STDIN "./logs/sdtin"
#define LOG_DEBUG "./logs/debug"
#define HOSTNAME_HTTPD  0 /* localhost */
#define PORTNAME_HTTPD "http"

pid_t fuzzer_pid=-1, server_pid=-1, connection_pid = -1;
const int number_signals = 15;
int signals[number_signals] = {SIGINT, SIGHUP, SIGQUIT, SIGILL, SIGTRAP,
                               SIGABRT, SIGBUS, SIGFPE, SIGSEGV, SIGPIPE,
                               SIGTERM, SIGSTKFLT, SIGSTOP, SIGTSTP, SIGUSR2};

struct sigaction prevhandlers_fuzz[number_signals];
struct sigaction prevhandlers_server[number_signals];
struct sigaction prevhandler_conn;

void handle_sig_fuzz(int, siginfo_t *, void *);
void handlers_on_fuzz();
void handlers_off_fuzz();
void handle_sig_server(int, siginfo_t *, void *);
void handlers_on_server();
void handlers_off_server();
void handler_connection_on();
void handler_connection_off();
void handle_sig_connection(int, siginfo_t *, void *);
void send_request(char *, size_t);
static void die(int line_number, const char *format, ...);
static void debug(const char *format, ...);


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

static void debug(const char *format, ...)
{
	va_list vargs;
	va_start(vargs, format);
    FILE *fptr;
    fptr = fopen(LOG_DEBUG, "a");
	vfprintf(fptr, format, vargs);
	fprintf(fptr, ".\n");
    fclose(fptr);
    va_end(vargs);
}

void send_request(char *request, size_t size_request){				
        FILE *fptr;
        fptr = fopen(LOG_REQUESTS, "a");
        if (fptr == NULL){
            die(0, "Error file opening");
        }

        const char *hostname = HOSTNAME_HTTPD;
        const char *portname = PORTNAME_HTTPD;
        struct addrinfo hints;

        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = 0;
        hints.ai_flags = AI_ADDRCONFIG;
        struct addrinfo *res = 0;

        int err = getaddrinfo(hostname, portname, &hints, &res);
        if (err != 0){
            die(0, "failed to resolve remote socket address (err=%d)", err);
        } 

        int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (fd == -1){
            die(0, "Socket: %s name: %s port:%d", strerror(errno), res->ai_canonname, portname);
        }

        //struct timeval tv;
        //tv.tv_sec = 0.5;
        //tv.tv_usec = 0;
        //setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
        fprintf(fptr, "Conectando...\n");
        if (connect(fd, res->ai_addr, res->ai_addrlen) == -1)
        {
            die(0, "Socket connect: %s", strerror(errno));
        }

        int written;
        if ((written = write(fd, request, size_request)) == -1)
            perror("write() error");
        else
            debug("REQUEST [written:%d size_request:%d]\n", written, size_request);

        fprintf(fptr, "REQUEST [written:%d size_request:%d]\n", written, size_request);

        freeaddrinfo(res);

        ssize_t size_response = 0, size_partial;
        int chunk_size = 1000;
        int max_resp_reads = MAX_SIZE_RESPONSE / chunk_size;
        char buf_r[MAX_SIZE_RESPONSE+1];
        memset(buf_r, 0, MAX_SIZE_RESPONSE+1);

        //TODO: timeout read
        for (;;)
        {
            printf("reading response...\n");
            if (max_resp_reads <= 0)
                break;
            size_partial = read(fd, buf_r+size_response, chunk_size);
            if(size_partial > 0){           
                max_resp_reads--;
                size_response += size_partial;
            }
            else if (size_partial < 0){
                if (errno != EINTR){
                    buf_r[size_response + 1] = '\0';
                    fprintf(fptr, "Partial response [size: %d] \n\n %s\n(EOF)\n ", buf_r);
                    fclose(fptr);
                    die(0, "Error reading response [read:%d, errno: %s]", size_response, strerror(errno));
                }
            } else {
                buf_r[size_response + 1] = '\0';
                fprintf(fptr, "RESPONSE [size: %d]\n\n%s\n(EOF)\n ", size_response, buf_r);
                break;
            }
        }
        debug("ending (read) response...\n");
        close(fd);
        fclose(fptr);
        return;
        //kill(ppid, SIGSTOP);
        //raise(SIGSTOP);
}

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
    debug("Signals handlers connections OFF\n");
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
    debug("Signals handlers server OFF\n");
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
    debug("Signals handlers fuzz OFF\n");
    fflush(stdout);
}

void handle_sig_server(int sig, siginfo_t *si, void *ucontext){
    handlers_off_server();
    if (sig != SIGUSR2)
    {
        debug("killing connection & server\n");
        fflush(stdout);
        if(connection_pid != -1)
            kill(connection_pid, sig);
        kill(server_pid, sig);
        kill(fuzzer_pid, sig);
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
        
        if(connection_pid != -1)
            sigqueue(connection_pid, SIGABRT, sv);
        
        sigqueue(server_pid, SIGUSR2, sv);
        sigqueue(fuzzer_pid, SIGABRT, sv);
    }
}

void handle_sig_fuzz(int sig, siginfo_t *si, void *ucontext){
    debug("Fuzz signal received in FUZZ: %d, pid: %d\n", sig, getpid());
    handlers_off_fuzz();
    if (sig != SIGUSR2)
    {
        fflush(stdout);
        if(connection_pid != -1)
            kill(connection_pid, sig);
        kill(server_pid, sig);
        kill(fuzzer_pid, sig);
    }  
    else 
    {
        union sigval sv;
        if(si != NULL)
            sv.sival_int = si->si_value.sival_int;
        else
            sv.sival_int = 0xD1E;
        if(connection_pid != -1)
            sigqueue(connection_pid, SIGUSR2, sv);
        sigqueue(server_pid, SIGUSR2, sv);
        sigqueue(fuzzer_pid, SIGABRT, sv);
    }
}

void handle_sig_connection(int sig, siginfo_t *si, void *ucontext){
    pid_t pid_conn;
    int status;
    union sigval sv;
    handler_off_connection();
    debug("Connection signal received: %d\n", sig);

    while ((pid_conn = waitpid(-1, &status, WNOHANG)) != -1);
    
    if(si != NULL)
        sv.sival_int = si->si_value.sival_int;
    else
        sv.sival_int = 0xD1E;

    if(connection_pid != -1)
    {
        sigqueue(connection_pid, SIGABRT, sv);
    }

    sigqueue(server_pid, SIGUSR2, sv);
    sigqueue(fuzzer_pid, SIGUSR2, sv);
}

    int main(int argc, char **argv)
    {

        fuzzer_pid = getpid();

        debug("Write something:\n");
        if ((server_pid = fork()) != 0) //PARENT: fuzzer
        {
            sleep(1); //waiting server UP
            FILE *fptr;

            handlers_on_fuzz();
            fptr = fopen("./fork.fuzzer.txt", "a");
            while (__AFL_LOOP(1000))
            {
                char buf[MAX_SIZE_REQUEST + 1];
                const int chunk_size = 1000;
                int max_reads = MAX_SIZE_REQUEST / chunk_size;
                ssize_t size_request = 0, size_partial;
                memset(buf, 0, MAX_SIZE_REQUEST);

                for (;;)
                {
                    if (max_reads <= 0)
                        break;
                    debug("Reading...\n");
                    max_reads--;
                    size_partial = read(0, buf + size_request, chunk_size);
                    if (size_partial > 0)
                    {
                        size_request += size_partial;
                    }
                    else if (size_partial < 0)
                    {
                        if (errno != EINTR)
                        {
                            buf[size_request + 1] = '\0';
                            fprintf(fptr, "STDIN ERROR (%s)\n Data:\n %s\(EOF)\n ", strerror(errno), buf);
                            fclose(fptr);
                            die(0, "Error reading request [read:%d, errno: %s]", size_request, strerror(errno));
                        }
                    }
                    else
                    {
                        buf[size_request + 1] = '\0';
                        fprintf(fptr, "RESPONSE [size: %d]\n\n%s\n(EOF)\n ", size_request, buf);
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
                    buf[MAX_SIZE_REQUEST - 5] = '\r';
                    buf[MAX_SIZE_REQUEST - 4] = '\n';
                    buf[MAX_SIZE_REQUEST - 3] = '\r';
                    buf[MAX_SIZE_REQUEST - 2] = '\n';
                    buf[MAX_SIZE_REQUEST - 1] = '\0';
                    size_request = MAX_SIZE_REQUEST;
                }

                debug("sending...\n");
                send_request(buf, size_request);
            }
            debug("Bye parent from fuzzer.\n");
            fclose(fptr);
            //kill(server_pid, SIGINT);
            exit(0);
        }
        else // CHILD: HTTP SERVER
        {
            int status = 0;
            handlers_on_server();
            handler_on_connection();
            if ((connection_pid = fork()) == 0) //CONNECTION
            {
                if (execve("./httpd", NULL, NULL) < 0)
                {
                    perror("error");
                }
                else
                {
                    debug("executed ./httpd\n");
                }
                debug("bye child execve\n");
                fflush(stdout);
            }
            else
            {
                while (wait(&status) > 0)
                    ;

                kill(connection_pid, SIGINT);
            }
            debug("Bye child from server.\n");
        }

        return 0;
}
