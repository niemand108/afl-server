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

#define MAX_SIZE_REQUEST 200000
#define MAX_SIZE_RESPONSE 200000
#define LOG_REQUESTS "./logs/requests"
#define LOG_STDIN "./logs/sdtin"
#define LOG_DEBUG "./logs/debug"
#define LOG_RESPONSE "./logs/response"
#define LOG_REQUEST "./logs/request"
#define HOSTNAME_HTTPD  0 /* localhost */
#define PORTNAME_HTTPD "http"

pid_t fuzzer_pid=-1, server_pid=-1, connection_pid = -1;
const int number_signals = 15;
int signals[number_signals] = {SIGINT, SIGHUP, SIGQUIT, SIGILL, SIGTRAP,
                               SIGABRT, SIGBUS, SIGFPE, SIGSEGV, SIGPIPE,
                               SIGTERM, SIGSTKFLT, SIGSTOP, SIGTSTP, SIGUSR2};

//struct sigaction prevhandlers_fuzz[number_signals];
//struct sigaction prevhandlers_server[number_signals];
//struct sigaction prevhandler_conn;

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
static void debug(const char *format, ...);
static void debug_response(int, char *, int);
static void debug_request(int, char *, int);

static void die(const char *format, ...)
{
    va_list vargs;
    va_start(vargs, format);
    fprintf(stderr, "DIE: ");
    vfprintf(stderr, format, vargs);
    fprintf(stderr, ".\n");
    va_end(vargs);
    debug("DIE: Signaling to [pid:%d] with SIGUSR & exit(1)", getpid());
    kill(SIGUSR2, getpid());
    exit(1);
}

static void debug(const char *format, ...)
{
    pid_t actual_pid = getpid();
    va_list vargs;
    va_start(vargs, format);
    FILE *fptr;
    fptr = fopen(LOG_DEBUG, "a");
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


static void debug_request(int id_request, char* request, int size_request)
{
    pid_t actual_pid = getpid();
    FILE *fptr;
    fptr = fopen(LOG_REQUEST, "a");
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    char t_s[64];
    assert(strftime(t_s, sizeof(t_s), "[%x %X]", tm));
    fprintf(fptr, "%s [pid:%d] ", t_s, actual_pid);
    fprintf(fptr, "REQUEST id=%d, size=%d\n", id_request,size_request);
    fprintf(fptr, "%s\n", request);
    fprintf(fptr, "(EOF)\n\n");
    fclose(fptr);
}

static void debug_response(int id_request, char * response, int size_response)
{
    pid_t actual_pid = getpid();
    FILE *fptr;
    fptr = fopen(LOG_RESPONSE, "a");
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    char t_s[64];
    assert(strftime(t_s, sizeof(t_s), "[%x %X]", tm));
    fprintf(fptr, "%s [pid:%d] ", t_s, actual_pid);
    fprintf(fptr, "RESPONSE id=%d, size=%d\n", id_request, size_response);
    fprintf(fptr, "%s\n", response);
    fprintf(fptr, "(EOF)\n\n");
    fclose(fptr);
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

    //TODO: timeout read
    for (;;)
    {
        debug("(id_req: %d) Reading response...", id_request);
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
    //kill(server_pid, SIGINT); //TODO SIGINT
    close(fd);
    return size_response ;
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

void handle_sig_default(int sig, siginfo_t *si, void *ucontext){
    debug("Unhandle sig: %d", sys_siglist[sig]);
}

void handler_default_on(){
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
    for (int s = 1; s <= 62; s++){
        if(!is_handled(s)){
            signal(s, SIG_DFL);
        }
    }
}


void handler_on_connection(){
    debug("Signals handlers ON for process connection");
    struct sigaction new_action;
    new_action.sa_handler = handle_sig_connection;
    sigemptyset (&new_action.sa_mask);
    new_action.sa_flags = 0;
    //sigaction (SIGCHLD, NULL, &prevhandler_conn);
    sigaction (SIGCHLD, &new_action, NULL);
}

void handler_off_connection(){
    debug("Signals handlers OFF for process connection");
    signal(SIGCHLD, SIG_DFL);
    //sigaction (SIGCHLD, &prevhandler_conn, NULL);
}

void handlers_on_server()
{
    debug("Signals handlers ON for server process");
    struct sigaction new_action;
    new_action.sa_handler = handle_sig_server;
    sigemptyset (&new_action.sa_mask);
    new_action.sa_flags = 0;

    for (int s = 0; s < number_signals; s++){
        //sigaction (signals[s], NULL, &(prevhandlers_server[s]));
        sigaction (signals[s], &new_action, NULL);
    }
}

void handlers_off_server(){
    debug("Signals handlers OFF for server process");
    for (int s = 0; s < number_signals; s++){
        signal(signals[s], SIG_DFL);
        //sigaction (signals[s], &(prevhandlers_server[s]), NULL);
    }    
}

void handlers_on_fuzz()
{
    debug("Signals handlers ON for FUZZ process");
    struct sigaction new_action;
    new_action.sa_handler = handle_sig_fuzz;
    sigemptyset (&new_action.sa_mask);
    new_action.sa_flags = 0;

    for (int s = 0; s < number_signals; s++){
        //sigaction (signals[s], NULL, &(prevhandlers_fuzz[s]));
        sigaction (signals[s], &new_action, NULL);
    }
}

void handlers_off_fuzz(){
    debug("Signals handlers OFF for FUZZ process");
    for (int s = 0; s < number_signals; s++){
        signal(signals[s], SIG_DFL);
        //sigaction (signals[s], &(prevhandlers_fuzz[s]), NULL);
    }
}


void handle_sig_server(int sig, siginfo_t *si, void *ucontext){
    debug("Server handler for --%s-- [pid: %d]", sys_siglist[sig], getpid());
    handlers_off_server();
    if (sig != SIGUSR2)
    {
        debug("(cont.) Signaling --signal:%s-- [to conn_pid:%d, serverpid:%d, fuzzer_pid:%d]",\
                sys_siglist[sig], connection_pid, server_pid, fuzzer_pid);

        if(connection_pid != -1)
            kill(connection_pid, sig);
        kill(server_pid, sig);
        kill(fuzzer_pid, sig); 
    }  
    else 
    {
        debug("Signal %s received in server: %d, pid: %d", sys_siglist[sig], getpid());
       // debug("(cont.) conn_pid:%d server_pid:%d fuzzer_pid:%d", connection_pid, server_pid, fuzzer_pid);
                
        union sigval sv;
        
        if(si != NULL)
            sv.sival_int = si->si_value.sival_int;
        else
            sv.sival_int = 0xD1E;
        debug("(cont.) Signal queue --signal:%s-- [to connpid:%d, serverpid:%d]", sys_siglist[SIGUSR2],\
                connection_pid, server_pid);
        if(connection_pid != -1)
            sigqueue(connection_pid, SIGUSR2, sv);
        
        sigqueue(server_pid, SIGUSR2, sv);
        //sigqueue(fuzzer_pid, SIGUSR2, sv);
    }
}

void handle_sig_fuzz(int sig, siginfo_t *si, void *ucontext){
    debug("Fuzz handler for --%s-- [pid: %d]", sys_siglist[sig], getpid());
    handlers_off_fuzz();
    if (sig != SIGUSR2)
    {
        debug("(cont.) Signaling --signal:%s-- [to conn_pid:%d, serverpid:%d]",\
                sys_siglist[sig], connection_pid, server_pid);
        if(connection_pid != -1)
            kill(connection_pid, sig);
        kill(server_pid, sig);
        //kill(fuzzer_pid, sig);
    }  
    else 
    {
        debug("Signal %s received in fuzzer: %d, pid: %d", sys_siglist[sig], getpid());
        //debug("(cont.) conn_pid:%d server_pid:%d fuzzer_pid:%d", connection_pid, server_pid);
        union sigval sv;
        if(si != NULL)
            sv.sival_int = si->si_value.sival_int;
        else
            sv.sival_int = 0xD1E;
        
        debug("(cont.) Signal queue --signal:%s-- [to connpid:%d, serverpid:%d]",
              sys_siglist[SIGUSR2], connection_pid, server_pid);

        if(connection_pid != -1)
            sigqueue(connection_pid, SIGUSR2, sv);
        sigqueue(server_pid, SIGUSR2, sv);
        //sigqueue(fuzzer_pid, SIGABRT, sv);
        exit(0);
    }
}

void handle_sig_connection(int sig, siginfo_t *si, void *ucontext){
    pid_t pid_conn;
    int status;
    union sigval sv;
    debug("Fuzz handler for --%s-- [pid: %d]", sys_siglist[sig], getpid());
    handler_off_connection();

    while ((pid_conn = waitpid(-1, &status, WNOHANG)) != -1);
    
    {
        if (WIFEXITED(status)) {
            debug("(cont.) [sig_ conn] exited, status=%d", WEXITSTATUS(status));
        } else if (WIFSIGNALED(status)) {
            debug("(cont.) [sig_ conn] killed by signal %d", WTERMSIG(status));
        }
        else if (WIFSTOPPED(status))
        {
            debug("(cont.)[sig_ conn] stopped by signal %d", WSTOPSIG(status));
        }
        else if (WIFCONTINUED(status))
        {
            debug("(cont.)[sig_ conn] continued");
        }
    } while (!WIFEXITED(status) && !WIFSIGNALED(status));

    if(si != NULL)
        sv.sival_int = si->si_value.sival_int;
    else
        sv.sival_int = 0xD1E;
    
    debug("(cont.) Signal queue --signal:%s-- [to serverpid:%d, fuzzerpid:%d, connpid:%d]",\
              sys_siglist[sig],server_pid, fuzzer_pid, connection_pid);

    sigqueue(server_pid, sig, sv);
    sigqueue(fuzzer_pid, sig, sv);

    if(connection_pid != -1)
    {
       sigqueue(connection_pid, SIGUSR2, sv);
    }
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
            while (__AFL_LOOP(1000))
            {
                loop++;
                char buf[MAX_SIZE_REQUEST + 1];
                const int chunk_size = 1000;
                int max_reads = MAX_SIZE_REQUEST / chunk_size;
                ssize_t size_request = 0, size_partial;
                memset(buf, 0, MAX_SIZE_REQUEST);

                for (;;)
                {
                    if (max_reads <= 0)
                        break;
                    debug("(loop:%d) Reading...", loop);
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

                debug("(loop:%d) sending... %s (size: %d)", loop, buf, size_request);
                int s_r = send_request(buf, size_request);
                if (s_r < 0)
                    debug("(loop:%d) sending error:%d", s_r);
            }
            debug("(loop:%d) Bye loop. Sending SIGUSER2 to server & exit.");
            kill(server_pid, SIGUSR2);
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
                    debug("executed ./httpd");
                }
                debug("bye child execve");
                
            }
            else
            {
                debug("waitpid pid:%d", connection_pid);
                int w = waitpid(connection_pid, &status, WUNTRACED | WCONTINUED);
                if (w == -1)
                {
                    perror("waitpid");
                    exit(EXIT_FAILURE);
                }

                {
                    if (WIFEXITED(status)) {
                        debug("[pid: %d exited] status=%d", connection_pid, WEXITSTATUS(status));
                    } else if (WIFSIGNALED(status)) {
                        debug("[pid: %d killed by signal %s]", connection_pid, sys_siglist[WTERMSIG(status)]);
                    }
                    else if (WIFSTOPPED(status))
                    {
                        debug("[pid: %d stopped by signal %s]", connection_pid, sys_siglist[WSTOPSIG(status)]);
                    }
                    else if (WIFCONTINUED(status))
                    {
                        debug("[pid: %d continued (sig c.)]", connection_pid);
                    }
                } while (!WIFEXITED(status) && !WIFSIGNALED(status));
            
                debug("ending waitpid, everybody must have done & return 0");
                //kill(server_pid, SIGUSR2);
                //kill(fuzzer_pid, SIGUSR2);
                return 0;
            }
        }
        return 0;
}
