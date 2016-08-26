// #define _GNU_SOURCE

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <fcntl.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>

#define PORT     4070
#define SECRET   "abc\n"
#define BUFF_MAX 512
#define REMBASH  "<rembash>\n"
#define OK       "<ok>\n"
#define ERROR    "<error>\n"

int run_protocol(int connect_fd);
int safe_write(const int fd, char const *msg);
int safe_read(const int fd, char const *expected);
void handle_client(int connect_fd);
void debug(int fd);

int main()
{
    int server_socket_fd;
    int client_socket_fd;
    int fork_status;
    struct sockaddr_in server_address;
    struct sockaddr_in client_address;

    server_socket_fd = socket(AF_INET, SOCK_STREAM, 0);

    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = htonl(INADDR_ANY);
    server_address.sin_port = htons(PORT);

    bind(server_socket_fd, (struct sockaddr *) &server_address, sizeof server_address);

    // create queue
    listen(server_socket_fd, 5);

    // Ignore exited children
    signal(SIGCHLD, SIG_IGN);
    while (1)
    {
        printf("Server is waiting\n");

        socklen_t client_len = sizeof client_address;
        client_socket_fd = accept(
                server_socket_fd,
                (struct sockaddr *) &client_address,
                &client_len
                );
        printf("got client\n");
        if (run_protocol(client_socket_fd) == 0)
        {

            // Protocol success
            if ((fork_status = fork()) == -1)
            {
                perror("Fork failed\n");
                exit(EXIT_FAILURE);
            }
            else if (fork_status == 0)
            {
              #ifdef DEBUG
                debug(client_socket_fd);
              #endif
                handle_client(client_socket_fd);
            }
        }

        // Close parent-process copy of file descriptor
        close(client_socket_fd);
    }
}

void debug(int fd)
{
    char *buff = (char *) malloc(512);
    size_t len = 512;
    dup2(fd, STDIN_FILENO);
    printf("// Debug\n");
    while ((len = read(fd, buff, 512)) > 0)
    {
      buff[len] = '\0';
      printf("Got: %s\n", buff);
      write(fd, buff, len + 1);
    }
    printf("// End debug\n");
}

void handle_client(int fd)
{
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDIN_FILENO);
    dup2(fd, STDERR_FILENO);
    close(fd);
    execlp("bash", "bash", "--noediting", "-i", NULL);
}

int run_protocol(int fd)
{
    if (safe_write(fd, REMBASH) ||
        safe_read(fd, SECRET) ||
        safe_write(fd, OK))
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

int safe_write(const int fd, char const *message)
{
    if ( write(fd, message, strlen(message)) == -1 )
    {
        perror("Failed to write\n");
        return 1;
    }
    return 0;
}

int safe_read(const int fd, char const *expected)
{
    char buff[BUFF_MAX];
    int read_len;

    if ( (read_len = read(fd, buff, BUFF_MAX)) <= 0)
    {
        perror("Error reading from client\n");
        return 1;
    }

    if ( (unsigned int) read_len != strlen(expected) ||
         strncmp(expected, buff, read_len))
    {
        perror("Client gave incorrect protocol\n");
        safe_write(fd, ERROR);
        return 1;
    }
    return 0;
}
