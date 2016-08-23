#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>

#define PORT 4070
#define SECRET "abc\n"
#define BUFF_MAX 512
#define REMBASH "<rembash>\n"
#define OK "<ok>\n"

void handle_client(int connect_fd);

int main() {
  int server_socket_fd, client_socket_fd;
  struct sockaddr_in server_address, client_address;

  server_socket_fd = socket(AF_INET, SOCK_STREAM, 0);

  server_address.sin_family = AF_INET;
  server_address.sin_addr.s_addr = htonl(INADDR_ANY);
  server_address.sin_port = htons(PORT);

  bind( server_socket_fd, (struct sockaddr *) &server_address, sizeof server_address);

  // create queue
  listen(server_socket_fd, 5);

  // Ignore exited children
  signal(SIGCHLD, SIG_IGN);
  while(1) {
    printf("Server waiting\n");
    socklen_t client_len = sizeof client_address;
    client_socket_fd = accept(server_socket_fd, (struct sockaddr*) &client_address, &client_len);
    if (fork() == 0) {
      handle_client(client_socket_fd);
    }
  }
}

void handle_client(int connect_fd) {
  char buffer[BUFF_MAX];
  int read_len;
  if ( write(connect_fd, REMBASH, strlen(REMBASH)) == -1) {
    perror("Server failed to write\n");
    exit(EXIT_FAILURE);
  };

  if ( (read_len = read(connect_fd, buffer, BUFF_MAX)) <= 0 ) {
    perror("Server received nothing from client\n");
    exit(EXIT_FAILURE);
  };

  if ( read_len != strlen(SECRET) || strncmp(SECRET, buffer, read_len) ) {
    perror("Incorrect secret key protocol\n");
    write(connect_fd, "<error>\n", 8);
    close(connect_fd);
  }

  if ( write(connect_fd, "<ok>\n", 5) == -1) {
    perror("Failed to write\n");
    exit(EXIT_FAILURE);
  }

  while ( (read_len = read(connect_fd, buffer, BUFF_MAX)) > 0) {
    buffer[read_len] = '\0';
    printf("Len: %d\nRecd: %s\n", read_len, buffer);
  }
}
