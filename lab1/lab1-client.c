#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

#define PORT 4070
#define SECRET "abc\n"
#define BUFF_MAX 512

int protocol(int connect_fd);

int main(int argc, char** argv) {

  int socket_fd;
  struct sockaddr_in socket_address;

  socket_fd = socket(AF_INET, SOCK_STREAM, 0);
  socket_address.sin_family = AF_INET;
  #ifdef DEBUG
  argv[1] = "127.0.0.1";
  #endif
  inet_aton(argv[1], &socket_address.sin_addr);
  socket_address.sin_port = htons(PORT);

  if ( connect(socket_fd, (struct sockaddr *)&socket_address, sizeof socket_address) == -1 ) {
    perror("Unable to connect");
    exit(EXIT_FAILURE);
  }

  char ch = 'G';
  write(socket_fd, &ch, 1);
  read(socket_fd, &ch, 1);
  printf("Char from server: %c\n", ch);
  close(socket_fd);
  exit(EXIT_SUCCESS);
}

int protocol (int connect_fd) {
  
}
