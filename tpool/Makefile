archive:
	gcc -Wall -Wpedantic -c -o tpool.o tpool.c -pthread
	ar rcs tpool.a tpool.o
shared:
	gcc -fPIC -Wall -Wpedantic -c -o tpool.o tpool.c -pthread
	gcc -shared -o tpool.so tpool.o
