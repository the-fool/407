#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <fcntl.h>
#include <pty.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#include "readline.c"

#define PORT     4070
#define SECRET   "<cs407rembash>\n"
#define BUFF_MAX 512
#define REMBASH  "<rembash>\n"
#define OK       "<ok>\n"
#define ERROR    "<error>\n"

// The connection handler will fork() 2 children to be
// collected in a sigaction
struct Child_Pids
{
    pid_t pty;
    pid_t socket_to_pty;
} CHILD_PIDS;

int init_socket();
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

    if ((server_socket_fd = init_socket()) == -1) {
      exit(EXIT_FAILURE);
    }
    // Ignore exited children
    signal(SIGCHLD, SIG_IGN);

    while (1)
    {
      #ifdef DEBUG
        printf("Server is waiting\n");
      #endif
        client_socket_fd = accept(server_socket_fd, (struct sockaddr *) NULL, NULL);
        if (client_socket_fd == -1)
        {
            perror("Socket accept failed\n");
            exit(EXIT_FAILURE);
        }
      #ifdef DEBUG
        printf("Received client\n");
      #endif
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
                handle_client(client_socket_fd);
            }
        }
        else
        {
          #ifdef DEBUG
            fprintf(stderr, "Client failed rembash protocol handshake\n");
          #endif
        }
        // Close parent-process copy of file descriptor
        close(client_socket_fd);
    }
}

int init_socket()
{
    int fd;
    struct sockaddr_in addr;

    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        perror("Socket creation failed");
        return -1;
    }
    int i = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &i, sizeof(i)))
    {
        perror("setsockopt: SO_REUSEADDR");
        return -1;
    }
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &i, sizeof(i)))
    {
        perror("setsockopt: TCP_NODELAY");
        return -1;
    }
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(PORT);

    if (bind(fd, (struct sockaddr *) &addr, sizeof addr) == -1)
    {
        perror("Bind failed");
        return -1;
    }

    // create queue
    if (listen(fd, 5) == -1)
    {
        perror("Listen failed\n");
        return -1;
    }

    return fd;
}

void handle_sigchld(int signo, siginfo_t *info, void *context)
{
    int status;
    int exit_code;
    pid_t first_terminated;
    pid_t to_terminate;

  #ifdef DEBUG
    printf("PID that raised signal: %d\n", info->si_pid);
  #endif

    if ( (first_terminated = waitpid((pid_t) (-1), &status, WNOHANG)) > 0)
    {
        exit_code = !(WIFEXITED(status) && !WEXITSTATUS(status));
        // Ascertain the remaining PID and terminate
        to_terminate = CHILD_PIDS.pty == first_terminated ? CHILD_PIDS.socket_to_pty : CHILD_PIDS.pty;
        kill(to_terminate, SIGINT);
        wait(NULL);
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

void handle_client(int fd)
{
    struct sigaction sa;

    sa.sa_sigaction = &handle_sigchld;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO | SA_RESTART | SA_NOCLDSTOP;

    if (sigaction(SIGCHLD, &sa, 0) == -1)
    {
        perror("Unable to setup sigaction");
        exit(EXIT_FAILURE);
    }

    int pty_fd;
    CHILD_PIDS.pty = forkpty(&pty_fd, NULL, NULL, NULL);
    if (CHILD_PIDS.pty == -1)
    {
        const char *err = "forkpty failed";
        perror(err);
        write(fd, err, strlen(err));
        return;
    }
    else if (CHILD_PIDS.pty == 0)
    {
        execlp("bash", "bash", NULL);
        perror("Error execing bash");
        exit(EXIT_FAILURE);
    }

    if ((CHILD_PIDS.socket_to_pty = fork()) == -1)
    {
        perror("fork failed");
        return;
    }

    int nread = 0;
    char buff[BUFF_MAX];
    if (CHILD_PIDS.socket_to_pty == 0)
    {
        while ((nread = read(fd, buff, 1)) > 0)
        {
            if (write(pty_fd, buff, 1) != 1)
            {
                perror("Failed writing to pty master");
                exit(EXIT_FAILURE);
            }
        }
    }
    else
    {
        while ((nread = read(pty_fd, buff, BUFF_MAX)) > 0)
        {
            if (write(fd, buff, nread) < 0)
            {
                perror("Write to socket failed");
                kill(CHILD_PIDS.socket_to_pty, SIGINT); // This call evokes sighandler, which cleans up and exits
            }
        }
    }
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
    if (write(fd, message, strlen(message)) == -1)
    {
        perror("Failed to write\n");
        return 1;
    }
    return 0;
}

int safe_read(const int fd, char const *expected)
{
    char *line;

    if ((line = readline(fd)) == NULL)
    {
        perror("Error reading from client\n");
        return 1;
    }

    if (strcmp(expected, line))
    {
        fprintf(stderr, "Client gave incorrect protocol\n");
        safe_write(fd, ERROR);
        return 1;
    }
    return 0;
}
