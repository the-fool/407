#define _GNU_SOURCE
#define _BSD_SOURCE

#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "readline.c"

#define PORT     4070
#define SECRET   "<cs407rembash>\n"
#define BUFF_MAX 512
#define REMBASH  "<rembash>\n"
#define OK       "<ok>\n"

int FD; // Global socket file-descriptor, for convenience

int safe_write(char const *message);
int safe_read(char const *expected);
int connect_to_server(char *host);
int run_protocol();
int read_socket_write_terminal();
int read_terminal_write_socket();
int fork_and_handle_io();
void handle_sigchld(int, siginfo_t *, void *);

int main(int argc, char **argv)
{
    int error_status;

    if (argc < 2)
    {
        printf("Usage: client HOST_IP");
        exit(EXIT_FAILURE);
    }

    // remove line buffering
    setbuf(stdout, NULL);

    if (connect_to_server(argv[1]) != 0)
    {
        exit(EXIT_FAILURE);
    }

  #ifdef DEBUG
    printf("Connected\n");
  #endif

    if (run_protocol() != 0)
    {
        fprintf(stderr, "Protocol failed. Exiting.\n");
        exit(EXIT_FAILURE);
    }

    error_status = fork_and_handle_io();

    if (close(FD) == -1)
    {
        perror("Failed to close socket\n");
        exit(EXIT_FAILURE);
    }

  #ifdef DEBUG
    printf("%d: Exiting: %d\n", getpid(), error_status);
  #endif
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
    else
    {
        return 0;
    }
}

int run_protocol()
{
    if (safe_read(REMBASH) ||
        safe_write(SECRET) ||
        safe_read(OK))
    {
        return 1;
    }
    else
    {
        return 0;
    }
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
        struct sigaction sa;
        sa.sa_sigaction = &handle_sigchld;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = SA_SIGINFO | SA_RESTART | SA_NOCLDSTOP;

        if (sigaction(SIGCHLD, &sa, 0) == -1)
        {
            perror("Unable to setup sigaction");
            return 1;
        }

        // Stash error status to use for later --
        //   If there was an IO failure, we still ought to
        //   collect the child process before returning error status
        err_status = read_socket_write_terminal();
        #ifdef DEBUG
        printf("Error status for parent: %d\n", err_status);
        #endif
        // Only reach here if parent's IO loop breaks before child's
        if (kill(child_pid, 9) == -1)
        {
            perror("Kill() failed");
            err_status = 1;
        }
        // unreachable, since signal handler for SIGCHLD will terminate process
        return err_status;
    }
}

void handle_sigchld(int signo, siginfo_t *info, void *context)
{
    int status;
    int exit_code;

  #ifdef DEBUG
    printf("PID that raised signal: %d\n", info->si_pid);
  #endif
    if (waitpid((pid_t) (-1), &status, WNOHANG) > 0)
    {
        // collected child
        exit_code = !(WIFEXITED(status) && !WEXITSTATUS(status));
      #ifdef DEBUG
        printf("Exiting: %d\n", exit_code);
      #endif
        exit(exit_code);
    }
    else
    {
        // SIGCHLD was raised erroneously
      #ifdef DEBUG
        printf("Recvd SIGCHLD with no child to collect\n");
      #endif
        return;
    }
}

int read_socket_write_terminal()
{
    char *buff = (char *) malloc(BUFF_MAX);
    size_t n = BUFF_MAX;
    ssize_t sz;

    while ((sz = read(FD, buff, n)) > 0)
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
    else
    {
        return 0;
    }
}

int read_terminal_write_socket()
{
    char *buff = (char *) malloc(BUFF_MAX);
    size_t n = BUFF_MAX;

    while (getline(&buff, &n, stdin) > 0)
    {
        if (safe_write(buff) != 0)
        {
            return 1;
        }
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
    char* line;

    if ((line = readline(FD)) == NULL)
    {
        perror("Error reading from server\n");
        return 1;
    }

    if (strcmp(expected, line))
    {
        fprintf(stderr, "Server gave incorrect protocol\n");
        return 1;
    }
    else
    {
        return 0;
    }
}
