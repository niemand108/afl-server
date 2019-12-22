default: 
	afl-clang-fast fuzzer.c -o fuzzer
	afl-clang-fast httpd.c -o httpd
clean:
	rm -f httpd fuzzer
