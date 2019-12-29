# afl-server

Basic AFL structure for a server (mini_httpd)
=============================================
```
+----------------+                +----------------+
|                |                |                |              +-------------------+
|   ./fuzzer     +--------------->+   _AFL_LOOP    +-------------->                   |
|                |                |                |              |      REQUEST      |
+-------------+--+                +----------------+              |                   |
              |                                                   +---------+---------+
              |                                                             |
              |                                                             |
              |                                                             |
              |                                                             |
              |                   +---------------+                         |
              |                   |               |               +---------v----------+
              |                   |  LAUNCH SERV. |               |                    |
              +------------------>+               +--------------->   PROCESS REQUEST  |
                                  +---------------+               |                    |
                                                                  +--------------------+
```
Requeriments 
============

It's necessary the compiler afl-clang-fast (llvm-mode). 


Make
====

$ make 

Running AFL fuzzer
==================

1. Create fuzzing directories:
mkdir -p fuzz/
mkdir -p in

2. Create a sample:
cat <<EOT >> in/test1
GET / HTTP/1.1
Host: localhost
User-Agent: curl/7.65.3
Accept: */*


EOT

3. Launch the AFL fuzzer:
afl-fuzz -t 5000 -i in/ -o fuzz/ ./fuzzer -p 8080 -u yourlinuxuser -D

Logs
====
```
./logs
├── debug                   general debugging info
├── request                 all the requests by id_request
└── response                all the responses (with the id_request associated)
```
