install:
	gcc -Wall -std=c99 -o client lab2-client.c
	gcc -Wall -std=c99 -o server lab2-server.c -lutil

debug:
	gcc -Wall -Werror -std=c99 -o client -D DEBUG lab2-client.c
	gcc -Wall -Werror -std=c99 -o server -D DEBUG lab2-server.c -lutil
