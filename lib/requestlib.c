#include "requestlib.h"

int send_request_stochastic(char *request, size_t size_request)
{

    fd_set set;
    struct timeval timeout;
    int id_request = rand();
    int number_chunks = random_in_range(1, 100);
    int fd;

    _debug_info("(id_req: %d) Conectando...\n", id_request);

    if ((fd = connect_to(HOSTNAME_HTTPD, PORTNAME_HTTPD, id_request)) < 0) {
        _debug_info("(id_req: %d) Failed to connect...\n", id_request);
        return -1;
    }

    int offset = 0;
    int written = 0;
    for (int c = 0; c < number_chunks; c++) {
        if (offset >= size_request)
            break;
        int t = random_in_range(TIMEOUT_USEC_MIN, TIMEOUT_USEC_MAX);
        set_timeout(fd, t);
        int write_until_offset;
        if (number_chunks - 1 == c) {
            //last chunk
            write_until_offset = size_request - 1;
        } else {
            write_until_offset = random_in_range(offset, offset + MAX_CHUNK_REQUEST);
        }
        int size_to_write = write_until_offset - offset + 1;
        written = send_request_chunk(fd, size_to_write, offset, request, size_request);
        if (written > 0) {
            //assert(written == size_to_write);
            if (written < size_to_write) {
                _debug_info("(id_req: %d) writen NOT COMPLETED:  only %d of %d bytes in [%d,%d] of %d total with chunk %d. Why?\n",
                            id_request, written, size_to_write, offset, write_until_offset, size_request, size_to_write);
                sleep(0.15); //for caught signals
            }
            offset += written;
            sleeping();
        } else if (written == 0) {
            _debug_info("(id_req: %d) writen 0 bytes in %d/%d with chunk %d.\n",
                        id_request, offset, size_request, size_to_write);
            sleep(0.15); //for caught signals
            continue;
        } else {
            _debug_info("(id_req: %d) error (%s) in %d/%d with chunk %d.\n?",
                        id_request, strerror(-written), offset, size_request, size_to_write);
            sleep(0.15); //for caught signals
            continue;
        }
    }

    _debug_info("(id_req: %d) HTTP (stochastic) REQUEST DONE [written:%d size_request:%d]\n",
                id_request, offset, size_request);

    _debug_request(id_request, request, size_request);

    assert(offset == size_request);

    char buf_resp[MAX_SIZE_RESPONSE + 1];
    memset(buf_resp, 0, MAX_SIZE_RESPONSE + 1);
    int offset_resp = 0;
    int read_resp = 0;
    number_chunks = random_in_range(1, 100);
    for (int c = 0; c < number_chunks; c++) {
        int t = random_in_range(TIMEOUT_USEC_MIN, TIMEOUT_USEC_MAX);
        set_timeout(fd, t);
        int read_until_offset;
        if (number_chunks - 1 == c) {
            //last chunk
            read_until_offset = MAX_SIZE_RESPONSE;
        } else {
            if (read_until_offset + MAX_CHUNK_RESPONSE <= MAX_SIZE_RESPONSE) {
                read_until_offset = random_in_range(offset_resp, offset_resp + MAX_CHUNK_RESPONSE);
            } else {
                read_until_offset = random_in_range(offset_resp, MAX_SIZE_RESPONSE);
            }
        }
        int size_to_read = read_until_offset - offset_resp + 1;
        read_resp = recv_response_chunk(fd, size_to_read, offset_resp, buf_resp); //, MAX_SIZE_RESPONSE);
        if (read_resp > 0) {
            offset_resp += read_resp;
            sleeping();
            if (read_resp < size_to_read) {
                _debug("(id_req: %d) read NOT COMPLETED. Possible finished response. Forcing last chunk.\n", id_request);
                c = number_chunks - 1;
            }
        } else if (read_resp == 0) {
            _debug_info("(id_req: %d) recv 0 bytes in offset %d with chunk %d. Response finished.\n",
                        id_request, offset_resp, size_to_read);
            sleep(0.15); //for caught signals
            break;
        } else {
            _debug_info("(id_req: %d) error (%s) in recv in offset %d, chunk %d. \n?",
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
    _debug_response(id_request, buf_resp, offset_resp);
    _debug_info("response (id:%d, size:%d) DONE\n", id_request, offset_resp);
    float p = percent_of_symbols(buf_resp);
    if (p > 0.05) {
        _debug_info("response (id:%d) with percent of symbols %f\n", id_request, p);
    }

    close(fd);
    return offset_resp;
}

int send_request(char *request, size_t size_request)
{

    fd_set set;
    struct timeval timeout;
    int id_request = rand();
    int fd;

    _debug_info("(id_req: %d) Conectando...\n", id_request);

    if ((fd = connect_to(HOSTNAME_HTTPD, PORTNAME_HTTPD, id_request)) < 0) {
        _debug_info("(id_req: %d) Failed to connect...\n", id_request);
        return -1;
    }
    set_timeout(fd, TIMEOUT_USEC_MAX);
    int written = 0;
    written = send_request_chunk(fd, size_request, 0, request, size_request);
    if (written > 0) {
        if (written < size_request) {
            _debug_info("(id_req: %d) writen NOT COMPLETED: only %d of %d bytes.\n",
                        id_request, written, size_request);
            sleep(0.15);
        }
    } else if (written == 0) {
        _debug_info("(id_req: %d) writen 0 bytes (size request:%d).\n",
                    id_request, size_request);
        sleep(0.15); //for caught signals
    } else {
        _debug_info("(id_req: %d) error (%s) (size request:%d).\n?",
                    id_request, strerror(-written), size_request);
        sleep(0.15); //for caught signals
    }

    _debug_info("(id_req: %d) HTTP (chunk max) REQUEST DONE [written:%d size_request:%d]\n",
                id_request, written, size_request);

    _debug_request(id_request, request, size_request);

    set_timeout(fd, TIMEOUT_USEC_MAX);

    char buf_resp[MAX_SIZE_RESPONSE + 1];
    memset(buf_resp, 0, MAX_SIZE_RESPONSE + 1);
    int read_resp = 0;
    int read_offset = 0;
    for (;;) {
        read_resp = recv_response_chunk(fd, MAX_SIZE_RESPONSE, read_offset, buf_resp);
        if (read_resp > 0) {
            read_offset += read_resp;
            continue;
        } else if (read_resp == 0) {
            _debug_info("(id_req: %d) recv 0 bytes. Response finished.\n", id_request);
            sleep(0.15); //for caught signals
            break;
        } else {
            _debug_info("(id_req: %d) error (%s) in recv. \n?",
                        id_request, strerror(-read_resp));
            sleep(0.15); //for caught signals
            break;
        }
    }

    if (read_offset < MAX_SIZE_RESPONSE) {
        buf_resp[read_offset + 1] = '\0';
        //offset_resp++;
    } else {
        buf_resp[MAX_SIZE_RESPONSE] = '\0';
        read_offset = MAX_SIZE_RESPONSE - 1;
    }
    _debug_response(id_request, buf_resp, read_offset);
    _debug_info("response (id:%d, size:%d) DONE\n", id_request, read_offset);
    float p = percent_of_symbols(buf_resp);
    if (p > 0.05) {
        _debug_info("response (id:%d) with percent of symbols %f\n", id_request, p);
    }

    close(fd);
    return read_offset;
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
        _debug_info("(id_req: %d) Failed to resolve remote socket address (err=%s)\n",
                    id_request, strerror(errno));
        freeaddrinfo(res);
        return -1;
    }

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd == -1) {
        _debug_info("(id_req: %d) Socket: %s name: %s port:%d\n", id_request,
                    strerror(errno), res->ai_canonname, portname);
        freeaddrinfo(res);
        return -1;
    }

    if (connect(fd, res->ai_addr, res->ai_addrlen) == -1) {
        close(fd);
        _debug_info("(id_req: %d) Socket connect error: %s\n", id_request, strerror(errno));
        return -1;
    }

    freeaddrinfo(res);

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
        _debug_info("offset >= size_request (%d >= %d) \n", offset, size_request);
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

int recv_response_chunk(int fd, int recv_chunk, int offset, char *buf_resp) //, int size_resp_max)
{
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

void sleeping()
{
    int usecs = random_in_range(0, TIMEOUT_USEC_MAX);

    if (usleep(usecs) < 0) {
        _debug_info("error %s", strerror(errno));
    }
}