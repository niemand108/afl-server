
CRYPT_LIB = 	-lcrypt
CC=				afl-clang-fast
CDEFS =			$(SSL_DEFS) $(SSL_INC)
CFLAGS =		-ggdb -DHAVE_INT64T -O $(CDEFS) -ansi -pedantic -U__STRICT_ANSI__ -Wall -Wpointer-arith -Wshadow -Wcast-qual -Wcast-align -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wredundant-decls -Wno-long-long
LDFLAGS =	
LDLIBS =		$(CRYPT_LIB) $(SSL_LIBS) $(SYSV_LIBS)
OPTIMIZATIONS = -O0
DEBUG = 		-DDEBUG_ON
default: 
	$(MAKE) clean
	cd lib/ && $(CC) $(DEBUG) $(OPTIMIZATIONS) -o util.o -ggdb -c util.c
	cd lib/ && $(CC) $(DEBUG) $(OPTIMIZATIONS) -o httpdsig.o -ggdb -c httpdsig.c
	cd lib/ && $(CC) $(DEBUG) $(OPTIMIZATIONS) -o fuzzerlib.o -ggdb -c fuzzerlib.c
	cd lib/ && $(CC) $(DEBUG) $(OPTIMIZATIONS) -o requestlib.o -ggdb -c requestlib.c
	$(CC) $(DEBUG) $(OPTIMIZATIONS) -g -ggdb lib/util.o lib/httpdsig.o -c httpd.c -o httpd
	$(CC) $(DEBUG) $(OPTIMIZATIONS) -c fuzzer.c -g -ggdb -o fuzzer.o
	if [ ! -d mini_httpd-1.30 ]; then \
		wget -qO- https://acme.com/software/mini_httpd/mini_httpd-1.30.tar.gz | tar xvz && \
		chmod ug+w -R mini_httpd-1.30 && \
		patch mini_httpd-1.30/mini_httpd.c patch/mini_httpd.patch && \
      		patch mini_httpd-1.30/Makefile patch/Makefile.patch; \
	fi
	cd mini_httpd-1.30 && $(MAKE) 
	$(CC) -DMINI_HTTPD_ $(DEBUG) $(OPTIMIZATIONS) lib/util.o fuzzer.o lib/fuzzerlib.o lib/requestlib.o lib/httpdsig.o mini_httpd-1.30/mini_httpd.o mini_httpd-1.30/match.o mini_httpd-1.30/tdate_parse.o $(LDLIBS) -o ./fuzzer; 
	mkdir -p logs
clean:
	if [ -d mini_httpd-1.30 ]; then \
		cd mini_httpd-1.30 && $(MAKE) clean; \
	fi
	rm -f httpd fuzzer httpd.o fuzzer.o 
	cd lib && rm -f util.o requestlib.o httpdsig.o fuzzerlib.o
	rm -fr logs
