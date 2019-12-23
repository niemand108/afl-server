# afl-server

Basic AFL structure for a server
================================

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

Requeriments 
============

It's necessary to have socat installed and afl-clang-fast (llvm-mode)

Make
====

$ make 

Logs
====
<<<<<<< HEAD

=======
>>>>>>> fb4165b548753d871955e6240e578d64439c87f3
In ./logs:
  debug: general debugging info
  debug-httpd: for httpd process info
  request: all the requests by id_request
<<<<<<< HEAD
  response: all the responses (with the id_request associated)
=======
  response: all the responses (with the id_request associated)


>>>>>>> fb4165b548753d871955e6240e578d64439c87f3
