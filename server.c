#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include<signal.h>

pid_t fuzzer_pid, server_pid;
__sighandler_t prevhandler;

void handle_sigsegv(int sig)
{
    //printf("SIGSEGV pid:%d fuzzerpid: %d serverpid:%d \n", getpid(), fuzzer_pid, server_pid);
    //abort();
    signal(SIGSEGV, prevhandler);
    kill(fuzzer_pid, SIGSEGV);
    kill(server_pid, SIGSEGV);
    kill(getpid(), SIGSEGV);
}

int main(int argc, char** argv) {
    
    fuzzer_pid = getpid();
    
    printf("Escribe algo para que pete:\n");

    if (fork() != 0)  //PARENT: fuzzer
    {
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
        fclose(fptr);
        exit(0);
    }
    else // CHILD: HTTP SERVER
    {
        server_pid = getpid();
        prevhandler = signal(SIGSEGV, handle_sigsegv);
        while (1) // Running http code
        {
            sleep(1);
            if (fork() == 0) //handle connection
            {
                sleep(1);
                raise(SIGSEGV);
                printf("Yet here (handle_connection) (%d)...\n", getpid());
                //abort();
            }
            else  //main process
            {
                while (sleep(1))
                {
                    printf("Yet here (server) (%d)...\n", getpid());
                }
            }
        }
    }
        
return 0;
}
