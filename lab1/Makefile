install:
	gcc -Wall -std=c99 -o client -D_BSD_SOURCE lab1-client.c
	gcc -Wall -std=c99 -o server lab1-server.c

debug:
	gcc -Wall -Werror -std=c99 -o client -D_BSD_SOURCE -D DEBUG lab1-client.c
	gcc -Wall -Werror -std=c99 -o server -D DEBUG lab1-server.c 
