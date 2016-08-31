#define _GNU_SOURCE
#define _BSD_SOURCE

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>

#define PORT     4070
#define SECRET   "cs407rembash"
#define BUFF_MAX 512
#define REMBASH  "<rembash>\n"
#define OK       "<ok>\n"

int FD;

int safe_write(char const *message);
int safe_read(char const *expected);
int connect_to_server(char *host);
int run_protocol();
int read_socket_write_terminal();
int read_terminal_write_socket();
int fork_and_handle_io();

int main(int argc, char **argv)
{
    int error_status;
    if (argc < 2)
    {
        perror("Usage: client HOST_IP");
        exit(EXIT_FAILURE);
    }

    // remove line buffering
    setbuf(stdout, NULL);

    if (connect_to_server(argv[1]) != 0)
    {
        exit(EXIT_FAILURE);
    }

    if (run_protocol() != 0)
    {
        perror("Protocol failed. Exiting.");
        exit(EXIT_FAILURE);
    }

    error_status = fork_and_handle_io();

    close(FD);

    exit(error_status);
}

int connect_to_server(char *host)
{
    struct sockaddr_in socket_address;
    char error_string[128];

    FD = socket(AF_INET, SOCK_STREAM, 0);
    if (FD == -1)
    {
        perror("Unable to create socket\n");
        return 1;
    }
    inet_aton(host, &socket_address.sin_addr);
    socket_address.sin_family = AF_INET;
    socket_address.sin_port = htons(PORT);

    if (connect(FD, (struct sockaddr *) &socket_address, sizeof socket_address) == -1)
    {
        sprintf(error_string, "Unable to connect to %s:%d", host, PORT);
        perror(error_string);
        return 1;
    }
  #ifdef DEBUG
    printf("Connected\n");
  #endif
    return 0;
}

int run_protocol()
{
    if (safe_read(REMBASH) ||
        safe_write(SECRET) ||
        safe_read(OK))
    {
        return 1;
    }

  #ifdef DEBUG
    printf("protocol success\n");
  #endif
    return 0;
}

int fork_and_handle_io()
{
    int child_pid;

    if ((child_pid = fork()) == -1)
    {
        perror("Unable to fork()");
        return 1;
    }
    else if (child_pid == 0)
    {
        return read_terminal_write_socket();
    }
    else
    {
        int err_status;
        dup2(FD, STDIN_FILENO);
        close(FD);
        // Stash error status to use for later --
        //   If there was an IO failure, we still ought to
        //   collect the child process before returning error status
        err_status = read_socket_write_terminal();

        int wait_res;
        int status;
        if ((wait_res = waitpid(child_pid, &status, WNOHANG)) == -1)
        {
            perror("Wait failed");
            return 1;
        }
        // If the child has not exited, kill it!
        else if (wait_res == 0)
        {
            kill(child_pid, 9);
            wait(&status);
        }
        #ifdef DEBUG
        printf("Collectd child: %d\n", status);
        #endif
        return err_status;
    }
}

int read_socket_write_terminal()
{
    char *buff = (char *) malloc(BUFF_MAX);
    size_t n = BUFF_MAX;
    ssize_t sz;

    while ((sz = read(STDIN_FILENO, buff, n)) > 0)
    {
        if (write(STDOUT_FILENO, buff, sz) == -1)
        {
            perror("Failed writing to stdout");
            return 1;
        }
    }
    if (sz == -1)
    {
        return 1;
    }
    return 0;
}

int read_terminal_write_socket()
{
    char *buff = (char *) malloc(BUFF_MAX);
    size_t n = BUFF_MAX;
    ssize_t line_size;

    while ((line_size = getline(&buff, &n, stdin)) > 0 && strncmp(buff, "exit\n", line_size) != 0)
    {
        if (safe_write(buff) != 0)
        {
            return 1; // On error, return
        }
        ;
    }
    if (safe_write("exit\n") != 0)
    {
        return 1;
    }
    return 0;
}

int safe_write(char const *message)
{
    if (write(FD, message, strlen(message)) == -1)
    {
        perror("Failed to write\n");
        return 1;
    }
    return 0;
}

int safe_read(char const *expected)
{
    char buff[BUFF_MAX];
    int read_len;

    if ((read_len = read(FD, buff, BUFF_MAX)) <= 0)
    {
        perror("Error reading from server\n");
        return 1;
    }

    if ((unsigned int) read_len != strlen(expected) || strncmp(expected, buff, read_len))
    {
        perror("Server gave incorrect protocol\n");
        return 1;
    }
    return 0;
}
