#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

#define PORT 4070
#define SECRET "abc\n"
#define BUFF_MAX 512
#define REMBASH "<rembash>\n"
#define OK "<ok>\n"

int FD;

void run_protocol();
void safe_write(const char* message);
void safe_read(const char* expected);
void main_loop();

int main(int argc, char** argv) {
  struct sockaddr_in socket_address;

  FD = socket(AF_INET, SOCK_STREAM, 0);
  socket_address.sin_family = AF_INET;
  #ifdef DEBUG
  argv[1] = "127.0.0.1";
  #endif
  inet_aton(argv[1], &socket_address.sin_addr);
  socket_address.sin_port = htons(PORT);

  if ( connect(FD, (struct sockaddr *)&socket_address, sizeof socket_address) == -1 ) {
    perror("Unable to connect");
    exit(EXIT_FAILURE);
  }

  run_protocol();

  close(FD);
  exit(EXIT_SUCCESS);
}

void run_protocol () {
  safe_read(REMBASH);
  safe_write(SECRET);
  safe_read(OK);

  main_loop();
}

void main_loop() {
  safe_write("HELLO!\n");
  sleep(3);
  safe_write("HOW DO YOU DO\n");
}

void safe_write(const char* message) {
  if ( write(FD, message, strlen(message)) == -1 ) {
    perror("Failed to write\n");
    exit(EXIT_FAILURE);
  }
}

void safe_read(const char* expected) {
  char buff[BUFF_MAX];
  int read_len;

  if ( (read_len = read(FD, buff, BUFF_MAX)) <= 0) {
    perror("Error reading from server\n");
    exit(EXIT_FAILURE);
  }

  if ( read_len != strlen(expected) || strncmp(expected, buff, read_len)) {
    perror("Server gave incorrect protocol\n");
    exit(EXIT_FAILURE);
  }
}
