# afl-server

Basic AFL structure for a server
================================
```
+----------------+                +----------------+
|                |                |                |              +-------------------+
|   AFL(fuzzer)  +--------------->+   _AFL_LOOP    +-------------->                   |
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

It's necessary the compiler afl-clang-fast (llvm-mode)

Make
====

$ make 

Logs
====
```
./logs
├── debug                   general debugging info
├── debug-httpd             for httpd process info
├── request                 all the requests by id_request
└── response                all the responses (with the id_request associated)
```
