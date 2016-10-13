install:
	gcc -Wall -std=c99 -o client lab3-client.c
	gcc -Wall -std=c99 -pthread -o server lab3-server.c -lutil -lrt

debug:
	gcc -Wall -Werror -std=c99 -o client -D DEBUG lab3-client.c
	gcc -Wall -Werror -std=c99 -pthread -o server -D DEBUG lab3-server.c -lutil -lrt
