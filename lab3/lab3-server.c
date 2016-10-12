#define _XOPEN_SOURCE 600  // for posix_openpt(), etc.
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <pty.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#include "readline.c"

#define PORT     4070
#define SECRET   "<cs407rembash>\n"
#define BUFF_MAX 4 * 1024
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
int handshake_protocol(int connect_fd);
int safe_write(const int fd, char const * msg);
int safe_read(const int fd, char const * expected);
int sigchld_to_sig_ign();
int eager_write(int fd, const char * const msg, size_t len);
void* handle_client(void * client_fd_ptr);
void debug(int fd);
void open_terminal_and_exec_bash(char * ptyslave);
void shuttle_bytes_between(int socket_fd, int pty_fd);

int main()
{
    int server_socket_fd;
    int client_fd;
    int* client_fd_ptr;
    pthread_t thread_id;

    if ((server_socket_fd = init_socket()) == -1)
    {
        exit(EXIT_FAILURE);
    }
    // Ignore exited children
    signal(SIGCHLD, SIG_IGN);

    while (1)
    {
#ifdef DEBUG
        printf("Server is waiting\n");
#endif
        if ((client_fd = accept(server_socket_fd, (struct sockaddr *) NULL, NULL)) == -1)
        {
            perror("Socket accept failed\n");
        }
        else
        {
          #ifdef DEBUG
          printf("Received client\n");
          #endif
          client_fd_ptr = (int *) malloc(sizeof(int));
          *client_fd_ptr = client_fd;
          if (pthread_create(&thread_id, NULL, &handle_client, (void *)client_fd_ptr)) {
              perror("failed to create pthread");
          }
          close(client_fd);
        }
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

void handle_sigchld(int signo, siginfo_t * info, void * context)
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
        exit(exit_code);
    }
}

void* handle_client(void * client_fd_ptr)
{
    char * ptyslave;
    int ptymaster_fd;
    int socket_fd = *(int *)client_fd_ptr;
    free(client_fd_ptr);
    if (handshake_protocol(socket_fd))
    {
        perror("Client failed protocol exchange");
        exit(EXIT_FAILURE);
    }

    if ((ptymaster_fd = posix_openpt(O_RDWR)) == -1)
    {
        perror("openpt failed");
        exit(EXIT_FAILURE);
    }
    unlockpt(ptymaster_fd);
    ptyslave = (char *) malloc(1024); // malloc first, to avoid race condition
    strcpy(ptyslave, ptsname(ptymaster_fd));

    switch (CHILD_PIDS.pty = fork())
    {
        case -1:
            perror("fork failed");
            exit(EXIT_FAILURE);
        case 0:
            close(ptymaster_fd);
            open_terminal_and_exec_bash(ptyslave);
            exit(EXIT_FAILURE);
    }
    shuttle_bytes_between(socket_fd, ptymaster_fd);

    while (waitpid(-1, NULL, WNOHANG) > 0)
    {
        ;
    }
    exit(EXIT_SUCCESS);
}

void shuttle_bytes_between(int socket_fd, int pty_fd)
{
    char buff[BUFF_MAX];
    int nread;
    struct sigaction sa;

    sa.sa_sigaction = &handle_sigchld;
    sa.sa_flags = SA_SIGINFO | SA_RESTART | SA_NOCLDSTOP;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGCHLD, &sa, 0) == -1)
    {
        perror("Unable to setup sigaction");
        exit(EXIT_FAILURE);
    }

    switch (CHILD_PIDS.socket_to_pty = fork())
    {
        case -1:
            perror("fork failed");
            sigchld_to_sig_ign();
            kill(CHILD_PIDS.pty, SIGTERM);
            exit(EXIT_FAILURE);
        case 0:
            while ((nread = read(socket_fd, buff, BUFF_MAX)) > 0)
            {
                if (eager_write(pty_fd, buff, nread) == -1)
                {
                    perror("Failed writing to pty master");
                    break;
                }
            }
            if (errno)
            {
                perror("Error reading from socket or writing to pty master");
            }
            else
            {
                fprintf(stderr, "Client connection closed unexpectedly\n");
            }
            exit(EXIT_FAILURE);
    }
    // Parent :: Read from PTY and write to SOCKET
    while ((nread = read(pty_fd, buff, BUFF_MAX)) > 0)
    {
        if (eager_write(socket_fd, buff, nread) == -1)
        {
            perror("Write to socket failed");
        }
    }

    sigchld_to_sig_ign();
    kill(CHILD_PIDS.pty, SIGTERM);
    kill(CHILD_PIDS.socket_to_pty, SIGTERM);
}

int sigchld_to_sig_ign()
{
    if (signal(SIGCHLD, SIG_IGN) == SIG_ERR)
    {
        perror("Failed to set SIGCHLD to SIG_IGN");
        return -1;
    }
    return 0;
}

void open_terminal_and_exec_bash(char * ptyslave)
{
    if (setsid() == -1)
    {
        perror("setsid failed");
        exit(EXIT_FAILURE);
    }
    int slave_fd;
    if ((slave_fd = open(ptyslave, O_RDWR)) == -1)
    {
        perror("Failed to open slave");
        exit(EXIT_FAILURE);
    }
    if ((dup2(slave_fd, STDIN_FILENO) == -1)
        || (dup2(slave_fd, STDOUT_FILENO) == -1)
        || (dup2(slave_fd, STDERR_FILENO) == -1))
    {
        perror("dup2 to either stdout, stdin, or stderr failed");
        exit(EXIT_FAILURE);
    }
    execlp("bash", "bash", NULL);
    perror("Failed to exec bash");
    exit(EXIT_FAILURE);
}

int handshake_protocol(int fd)
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

int safe_write(const int fd, char const * message)
{
    if (write(fd, message, strlen(message)) == -1)
    {
        perror("Failed to write\n");
        return 1;
    }
    return 0;
}

int safe_read(const int fd, char const * expected)
{
    char * line;

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

int eager_write(int fd, const char * const msg, size_t len)
{
    static size_t accum = 0;
    static int nwrote = 0;

    do
    {
        if ((nwrote = write(fd, msg + accum, len - accum)) == -1)
        {
            break;
        }
        accum += nwrote;
    }
    while (accum < len);
    accum = 0;
    nwrote = 0;
    return nwrote;
}
