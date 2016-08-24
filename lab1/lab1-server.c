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

void run_protocol(int connect_fd);
void safe_write(const int fd, char const* msg);
void safe_read(const int fd, char const* expected);
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
    printf("Server is waiting\n");
    socklen_t client_len = sizeof client_address;
    client_socket_fd = accept(server_socket_fd, (struct sockaddr*) &client_address, &client_len);
    if (fork() == 0) {
      handle_client(client_socket_fd);
    }
  }
}

void handle_client(int fd) {
  char buffer[BUFF_MAX];
  int read_len;

  run_protocol(fd);

  while ( (read_len = read(fd, buffer, BUFF_MAX)) > 0) {
    buffer[read_len] = '\0';
    printf("Recd: %s\n", buffer);
  }
}

void run_protocol(int fd) {
  safe_write(fd, REMBASH);
  safe_read(fd, SECRET);
  safe_write(fd, OK);
}

void safe_write(const int fd, char const* message) {
  if ( write(fd, message, strlen(message)) == -1 ) {
    perror("Failed to write\n");
    exit(EXIT_FAILURE);
  }
}

void safe_read(const int fd, char const* expected) {
  char buff[BUFF_MAX];
  int read_len;

  if ( (read_len = read(fd, buff, BUFF_MAX)) <= 0) {
    perror("Error reading from client\n");
    exit(EXIT_FAILURE);
  }

  if ( read_len != strlen(expected) || strncmp(expected, buff, read_len)) {
    perror("Client gave incorrect protocol\n");
    exit(EXIT_FAILURE);
  }
}
