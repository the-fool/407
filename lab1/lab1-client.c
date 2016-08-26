#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

#define PORT     4070
#define SECRET   "abc\n"
#define BUFF_MAX 512
#define REMBASH  "<rembash>\n"
#define OK       "<ok>\n"

int FD;

void run_protocol();
void safe_write(char const *message);
void safe_read(char const *expected);
void main_loop();
void read_socket();
void read_terminal();

int main(int argc, char **argv)
{
    struct sockaddr_in socket_address;
    setbuf(stdout, NULL);
  #ifdef DEBUG
    argv[1] = "127.0.0.1";
  #endif

    FD = socket(AF_INET, SOCK_STREAM, 0);
    inet_aton(argv[1], &socket_address.sin_addr);
    socket_address.sin_family = AF_INET;
    socket_address.sin_port = htons(PORT);

    if ( connect(FD, (struct sockaddr *) &socket_address, sizeof socket_address) == -1 )
    {
        perror("Unable to connect");
        exit(EXIT_FAILURE);
    }
    printf("Connected\n");
    run_protocol();
    printf("protocol success\n");
    main_loop();
    close(FD);
    exit(EXIT_SUCCESS);
}

void run_protocol()
{
    safe_read(REMBASH);
    safe_write(SECRET);
    safe_read(OK);
}

void main_loop()
{
    int child_pid;

    if ( (child_pid = fork()) == -1 )
    {
        perror("Unable to fork()\n");
        exit(EXIT_FAILURE);
    }
    else if ( child_pid == 0 )
    {
        read_terminal();
    }
    else
    {
        dup2(FD, STDIN_FILENO);
        close(FD);
        read_socket();
    }
}

void read_socket()
{
    char *buff = (char *) malloc(BUFF_MAX);
    size_t n = BUFF_MAX;
    ssize_t sz;
    while ((sz = read(STDIN_FILENO, buff, n)) > 0)
    {
        //buff[line_size - 1] = '\0'; // remove newline
        write(STDOUT_FILENO, buff, sz);
    }
}

void read_terminal()
{
    char *buff = (char *) malloc(BUFF_MAX);
    size_t n = BUFF_MAX;
    ssize_t line_size;

    while (1)
    {
        line_size = getline(&buff, &n, stdin);
        write(FD, buff, line_size);
    }
}

void safe_write(char const *message)
{
    if ( write(FD, message, strlen(message)) == -1 )
    {
        perror("Failed to write\n");
        exit(EXIT_FAILURE);
    }
}

void safe_read(char const *expected)
{
    char buff[BUFF_MAX];
    int read_len;

    if ( (read_len = read(FD, buff, BUFF_MAX)) <= 0)
    {
        perror("Error reading from server\n");
        exit(EXIT_FAILURE);
    }

    if ( (unsigned int) read_len != strlen(expected) || strncmp(expected, buff, read_len))
    {
        perror("Server gave incorrect protocol\n");
        exit(EXIT_FAILURE);
    }
}
