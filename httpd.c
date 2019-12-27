#include "httpdsig.h"
#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    srand(time(NULL));
    set_server_pid(getpid());
    handlers_httpd_on();
    handler_others_on();

    pid_t chld = fork();
    if (chld == 0) {
        char *args[] = {"socat", "tcp6-listen:8080,reuseaddr,fork", "SYSTEM:\"/bin/echo hola\"", NULL};
        execvp("/usr/bin/socat", args);
    } else //SELECT
    {
        set_conn_pid(chld);
        while (1) {
            debug_info("HTTPD-Fork | Sleeping\n");
            if (sleep(1000) != 0)
                debug_info("HTTPD-Fork | waken from sleep for handling a signal\n");
        }
    }
    return 0;
}
