
CRYPT_LIB = 	-lcrypt
CC=				afl-clang-fast
CDEFS =		$(SSL_DEFS) $(SSL_INC)
CFLAGS =	-ggdb -DHAVE_INT64T -O $(CDEFS) -ansi -pedantic -U__STRICT_ANSI__ -Wall -Wpointer-arith -Wshadow -Wcast-qual -Wcast-align -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wredundant-decls -Wno-long-long
LDFLAGS =	
LDLIBS =	$(CRYPT_LIB) $(SSL_LIBS) $(SYSV_LIBS)

default: 
	$(MAKE) clean
	$(CC) -o util.o -ggdb -c util.c
	$(CC) -o httpdsig.o -ggdb -c httpdsig.c
	cd mini_httpd-1.30 && $(MAKE) 
	$(CC) -g -ggdb util.o httpdsig.o -c httpd.c -o httpd
	#$(CC) -ggdb fuzzer.c
	$(CC) -c fuzzer.c -g -ggdb -o fuzzer.o
	$(CC) util.o fuzzer.o httpdsig.o mini_httpd-1.30/mini_httpd.o mini_httpd-1.30/match.o mini_httpd-1.30/tdate_parse.o $(LDLIBS) -o ./fuzzer
	mkdir -p logs
clean:
	cd mini_httpd-1.30 && $(MAKE) clean
	rm -f httpd fuzzer httpd.o fuzzer.o util.o
	rm -fr logs
