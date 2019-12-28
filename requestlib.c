#include "requestlib.h"

int send_request_stochastic(char *request, size_t size_request)
{

    fd_set set;
    struct timeval timeout;
    int id_request = rand();
    int number_chunks = random_in_range(1, 100);
    int fd;

    debug_info("(id_req: %d) Conectando...\n", id_request);

    if ((fd = connect_to(HOSTNAME_HTTPD, PORTNAME_HTTPD, id_request)) < 0) {
        debug_info("(id_req: %d) Failed to connect...\n", id_request);
        return -1;
    }

    int offset = 0;
    int written = 0;
    for (int c = 0; c < number_chunks; c++) {
        if (offset >= size_request)
            break;
        int t = random_in_range(TIMEOUT_USEC_MIN, TIMEOUT_USEC_MAX);
        set_timeout(fd, t);
        int future_offset;
        if (number_chunks - 1 == c) {
            //last chunk
            future_offset = size_request;
        } else {
            future_offset = random_in_range(offset, size_request);
        }
        int size_to_write = future_offset - offset + 1;
        written = send_request_chunk(fd, size_to_write, offset, request, size_request);
        if (written > 0) {
            // TODOdebug_info("(id_req: %d) writen %d bytes in [%d,%d] of %d total with chunk %d.\n",
            //           id_request, written, offset, future_offset, size_request, size_to_write);

            //assert(written == size_to_write);
            if (written < size_to_write) {
                debug_info("(id_req: %d) writen NOT COMPLETED:  only %d of %d bytes in [%d,%d] of %d total with chunk %d. Why?\n",
                           id_request, written, size_to_write, offset, future_offset, size_request, size_to_write);
            }
            offset += written;
        } else if (written == 0) {
            debug_info("(id_req: %d) writen 0 bytes in %d/%d with chunk %d. Why?\n",
                       id_request, offset, size_request, size_to_write);
            sleep(0.15); //for caught signals
            continue;
        } else {
            debug_info("(id_req: %d) error (%s) in %d/%d with chunk %d. Why\n?",
                       id_request, strerror(-written), offset, size_request, size_to_write);
            sleep(0.15); //for caught signals
            continue;
        }
    }

    debug_info("(id_req: %d) HTTP (stochastic) REQUEST DONE [written:%d size_request:%d]\n",
               id_request, offset, size_request);

    debug_request(id_request, request, size_request);

    assert(offset == size_request);

    char buf_resp[MAX_SIZE_RESPONSE + 1];
    memset(buf_resp, 0, MAX_SIZE_RESPONSE + 1);
    int offset_resp = 0;
    int read_resp = 0;
    number_chunks = random_in_range(1, 100);
    for (int c = 0; c < number_chunks; c++) {
        int t = random_in_range(TIMEOUT_USEC_MIN, TIMEOUT_USEC_MAX);
        set_timeout(fd, t);
        int future_offset_resp;
        if (number_chunks - 1 == c) {
            //last chunk
            future_offset_resp = MAX_SIZE_RESPONSE;
        } else {
            future_offset_resp = random_in_range(offset_resp, offset_resp + 100);
        }
        int size_to_read = future_offset_resp - offset_resp + 1;
        read_resp = recv_response_chunk(fd, size_to_read, offset_resp, buf_resp, MAX_SIZE_RESPONSE);
        if (read_resp > 0) {
            //TODOdebug_info("(id_req: %d) Request: chunck(%d) with size %d received (Remaining in read %d)\n",
            //          id_request, c, read_resp, (size_to_read - read_resp));
            offset_resp += read_resp;
            if (read_resp < size_to_read) {
                _debug("(id_req: %d) read NOT COMPLETED. Possible finished response. Forcing last chunk.\n", id_request);
                c = number_chunks - 1;
            }
        } else if (read_resp == 0) {
            debug_info("(id_req: %d) recv 0 bytes in offset %d with chunk %d. Response finished.\n",
                       id_request, offset_resp, size_to_read);
            sleep(0.15); //for caught signals
            break;
        } else {
            debug_info("(id_req: %d) error (%s) in recv in offset %d, chunk %d. \n?",
                       id_request, strerror(-read_resp), offset_resp, c);
            sleep(0.15); //for caught signals
            break;
        }
    }

    if (offset_resp <= MAX_SIZE_RESPONSE) {
        buf_resp[offset_resp] = '\0';
        //offset_resp++;
    } else {
        buf_resp[MAX_SIZE_RESPONSE] = '\0';
        offset_resp = MAX_SIZE_RESPONSE;
    }
    debug_response(id_request, buf_resp, offset_resp);
    debug_info("response (id:%d, size:%d) DONE\n", id_request, offset_resp);
    float p = percent_of_symbols(buf_resp);
    if (p > 0.05) {
        debug_info("response (id:%d) with percent of symbols %f\n", id_request, p);
    }

    close(fd);
    return offset_resp;
}

int send_request(char *request, size_t size_request)
{
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
    if (err != 0) {
        die("(id_req: %d) Failed to resolve remote socket address (err=%d)\n",
            id_request, err);
    }

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd == -1) {
        die("(id_req: %d) Socket: %s name: %s port:%d\n", id_request,
            strerror(errno), res->ai_canonname, portname);
    }

    struct timeval timeout;

    timeout.tv_sec = 0; //0;
    timeout.tv_usec = TIMEOUT_USEC_MAX;
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (struct timeval *)&timeout, sizeof(struct timeval));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *)&timeout, sizeof(struct timeval));

    if (connect(fd, res->ai_addr, res->ai_addrlen) == -1) {
        close(fd);
        die("(id_req: %d) Socket connect: %s\n", id_request, strerror(errno));
    }
    debug_info("(id_req: %d) Conectando...\n", id_request);

    int written;

    if ((written = send(fd, request, size_request, 0)) <= 0) { // write(fd, request, size_request)) == -1) {
        debug_info("(id_req: %d) write socket:  %s\n", id_request,
                   strerror(errno));
        close(fd);
        return -2;
    }
    debug_info("(id_req: %d) HTTP REQUEST DONE [written:%d size_request:%d]\n",
               id_request, written, size_request);
    assert(written == size_request);

    debug_request(id_request, request, size_request);

    freeaddrinfo(res);

    ssize_t size_response = 0, size_partial;
    int chunk_size = 1000;
    int max_resp_reads = MAX_SIZE_RESPONSE / chunk_size;
    char buf_r[MAX_SIZE_RESPONSE + 1];
    memset(buf_r, 0, MAX_SIZE_RESPONSE + 1);

    debug_info("(id_req: %d) Reading response... | ", id_request);
    int max_try = 10;

    for (;;) {
        if (max_resp_reads <= 0) {
            debug_info("HTTP RESPONSE (max) [size: %d])\n", size_response);
            break;
        }
        size_partial = recv(fd, buf_r + size_response, chunk_size, 0); // read(fd, buf_r + size_response, chunk_size);
        if (size_partial > 0) {
            max_resp_reads--;
            size_response += size_partial;
            debug_info("response chunk %d\n", size_response);
        } else if (size_partial == 0) {
            if (size_response > 0) {
                debug_info("HTTP (partial) RESPONSE [size: %d])\n", size_response);
                break;
            }
            debug_info("response 0 bytes: possible crash. Trying %d/10\n", (10 - max_try));
            if (max_try > 0) {
                max_try--;
            } else if (max_try <= 0) {
                debug_info("partial response (max-tries) %d bytes: possible crash. Skipping out.\n");
                sleep(0.1); //for caught signals
                break;
            }
        } else if (size_partial < 0) {
            if (errno != EINTR) {
                close(fd);
                snprintf(request, 64, "timeout(size:%d, err:%s, id:%d)", size_response, strerror(errno), id_request);
                debug_info("%s\n", request);
                debug_response(id_request, request, strlen(request));
                return -1;
            }
        }
    }
    assert(size_request < MAX_SIZE_RESPONSE);
    if (buf_r[size_response] != '\0') {
        size_response++;
        buf_r[size_response] = '\0';
    }

    debug_response(id_request, buf_r, size_response);

    float p = percent_of_symbols(buf_r);
    if (p > 0.05) {
        debug_info("response (id:%d) with percent of symbols %f\n", id_request, p);
    }

    close(fd);
    return size_response;
}

int connect_to(char *hostname, char *portname, int id_request)
{

    struct addrinfo hints;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = 0;
    hints.ai_flags = AI_ADDRCONFIG;
    struct addrinfo *res = 0;

    int err = getaddrinfo(hostname, portname, &hints, &res);
    if (err != 0) {
        debug_info("(id_req: %d) Failed to resolve remote socket address (err=%s)\n",
                   id_request, strerror(errno));
        freeaddrinfo(res);
        return -1;
    }

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd == -1) {
        debug_info("(id_req: %d) Socket: %s name: %s port:%d\n", id_request,
                   strerror(errno), res->ai_canonname, portname);
        freeaddrinfo(res);
        return -1;
    }
    freeaddrinfo(res);
    if (connect(fd, res->ai_addr, res->ai_addrlen) == -1) {
        close(fd);
        debug_info("(id_req: %d) Socket connect error: %s\n", id_request, strerror(errno));
        return -1;
    }
    return fd;
}

void set_timeout(int fd, int microseconds)
{
    struct timeval timeout;
    timeout.tv_sec = 0; //0;
    timeout.tv_usec = microseconds;
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (struct timeval *)&timeout, sizeof(struct timeval));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *)&timeout, sizeof(struct timeval));
    return;
}

int send_request_chunk(int fd, int size_chunk, int offset, char *request, int size_request)
{
    if (offset >= size_request) {
        debug_info("offset >= size_request (%d >= %d) \n", offset, size_request);
        return -1;
    }
    if (offset + size_chunk >= size_request)
        size_chunk = size_request - offset;

    int size_send = send(fd, request + offset, size_chunk, 0);
    if (size_send > 0) {
        return size_send;
    } else if (size_send == 0) {
        return 0;
    } else if (size_send < 0) {
        if (errno != EINTR) {
            return -errno;
        }
    }
}

int recv_response_chunk(int fd, int recv_chunk, int offset, char *buf_resp, int size_resp_max)
{

    if (offset >= size_resp_max) {
        debug_info("offset >= size_request (%d >= %d) \n", offset, size_resp_max);
        return -1;
    }
    if (offset + recv_chunk >= size_resp_max) {
        debug_info("last chunk (reached limit buffer)\n");
        recv_chunk = size_resp_max - offset;
    }

    int size_resp = recv(fd, buf_resp + offset, recv_chunk, 0);
    if (size_resp > 0) {
        return size_resp;
    } else if (size_resp == 0) {
        return 0;
    } else if (size_resp < 0) {
        if (errno != EINTR) {
            return -errno;
        }
    }
}

int random_in_range(int min, int max)
{
    if (min > max) {
        int t = min;
        max = min;
        min = t;
    }
    return (rand() % (max + 1 - min) + min);
}