#ifndef _REQUESTLIB_H_
#define _REQUESTLIB_H_
#include "util.h"
#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>

#define LOG_RESPONSE "./logs/response"
#define LOG_REQUEST "./logs/request"
#define MAX_SIZE_REQUEST 200000
#define MAX_SIZE_RESPONSE 200000
#define HOSTNAME_HTTPD 0 /* localhost */
#define PORTNAME_HTTPD "8080"
#define TIMEOUT_USEC_MAX 30000
#define TIMEOUT_USEC_MIN 5000
#define LOG_DEBUG "./logs/debug"

extern int send_request(char *, size_t);
extern int send_request_stochastic(char *, size_t);
int send_request_chunk(int, int, int, char *, int);
int recv_response_chunk(int, int, int, char *, int);
int random_in_range(int, int);
void set_timeout(int, int);

#endif