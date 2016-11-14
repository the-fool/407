archive:
	gcc -Wall -Wpedantic -c -o tpool.o tpool.c -pthread
	ar rcs tpoola tpool.o
shared:
	gcc -fPIC -Wall -Wpedantic -c -o tpool.o tpool.c -pthread
	gcc -shared -o tpoos.so tpool.o
