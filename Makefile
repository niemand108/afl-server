default: 
	afl-clang-fast -ggdb fuzzer.c -o fuzzer
	afl-clang-fast -ggdb httpd.c -o httpd
	mkdir -p logs
clean:
	rm -f httpd fuzzer
	rm -fr logs
