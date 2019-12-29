#include "lib/fuzzerlib.h"
#include "lib/requestlib.h"
#include "lib/util.h"
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    srand(time(NULL));

#ifdef DEBUG_ON
    open_log(LOG_DEBUG);
    open_log(LOG_REQUEST);
    open_log(LOG_RESPONSE);
#endif

    set_fuzz_fuzzer_pid(getpid());
    handler_others_on();
    _debug_info("Write something:\n");

    pid_t server_pid = fork();
    if (server_pid != 0) // PARENT: fuzzer
    {
        set_fuzz_server_pid(server_pid);
        sleep(1); // waiting server UP

        handlers_on_fuzz();
        int loop = 0;
        while (__AFL_LOOP(1000000)) {
            //while (1) {
            loop++;
            char buf[MAX_SIZE_REQUEST + 1];
            const int chunk_size = 1000;
            int max_reads = MAX_SIZE_REQUEST / chunk_size;
            ssize_t size_request = 0, size_partial;
            memset(buf, 0, MAX_SIZE_REQUEST);

            _debug_info("(loop:%d) Reading stdin...\n", loop);
            for (;;) {
                if (max_reads <= 0)
                    break;
                max_reads--;
                size_partial = read(0, buf + size_request, chunk_size);
                if (size_partial > 0) {
                    size_request += size_partial;
                } else if (size_partial < 0) {
                    if (errno != EINTR) {
                        _debug_info("(loop:%d) STDIN ERROR (%s)\n", loop,
                                    strerror(errno));
                        die("Error reading request [read:%d, errno: %s]\n",
                            size_request, strerror(errno));
                    }
                } else {
                    break;
                }
            }
            if (size_request + 7 < MAX_SIZE_REQUEST) {
                buf[size_request] = '\r';
                buf[size_request + 1] = '\n';
                buf[size_request + 2] = '\r';
                buf[size_request + 3] = '\n';
                buf[size_request + 4] = '\r';
                buf[size_request + 5] = '\n';
                buf[size_request + 6] = '\0';
                size_request += 7;
            } else {
                _debug_info("(loop:%d) MAX_SIZE_REQUEST\n", loop);
                buf[size_request - 6] = '\r';
                buf[size_request - 5] = '\n';
                buf[MAX_SIZE_REQUEST - 4] = '\r';
                buf[MAX_SIZE_REQUEST - 3] = '\n';
                buf[MAX_SIZE_REQUEST - 2] = '\r';
                buf[MAX_SIZE_REQUEST - 1] = '\n';
                buf[MAX_SIZE_REQUEST - 0] = '\0';
                size_request = MAX_SIZE_REQUEST;
            }

            _debug_info("(loop:%d) sending... (size: %d)\n", loop, size_request);
            int s_r = send_request(buf, size_request);
            //int s_r = send_request_stochastic(buf, size_request);
            if (s_r < 0)
                _debug_info("(loop:%d) sending error:%d\n", loop, s_r);
        }

        _debug_info("(loop:%d) | Final Loop\n", loop);

        kill(get_fuzz_server_pid(), SIGINT);
        sleep(1); //for caught signals

#ifdef DEBUG_ON
        close_all_log();
#endif

        return 0;
    } else // CHILD: HTTP SERVER
    {
        set_fuzz_server_pid(getpid()); // remove
        int status = 0;
        pid_t connection_pid = fork();
        if (connection_pid == 0) {
            set_fuzz_conn_pid(getpid());
#ifdef MINI_HTTPD_
            _debug_info("Calling mini_httpd with args: ");
            for (int c = 1; c < argc; c++) {
                _debug("arg[%d]=%s ", c, argv[c]);
            }
            _debug("\n");
            indirect_main(argc, argv);
#else
            if (execve("./httpd", NULL, NULL) < 0) {
                perror("error");
            }
#endif
        } else {
            handlers_on_server();

            while (1) {
                _debug_info("Server-Fork | Sleeping\n");
                if (sleep(1000) != 0)
                    _debug_info("Server-Fork | waken from sleep for handling a signal\n");
            }
            return 0;
        }
    }
    return 0;
}
