#define _XOPEN_SOURCE 600
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
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#include "readline.c"
#include "tpool.h"

#define BUFF_MAX    4 * 1024
#define MAX_CLIENTS 64 * 1024
#define PORT        4070
#define SECRET      "<cs407rembash>\n"
#define REMBASH     "<rembash>\n"
#define OK          "<ok>\n"
#define ERROR       "<error>\n"

typedef enum client_state
{
    secret,
    complete
} client_state_t;

typedef struct client
{
    int socket_fd;
    int pty_fd;
    client_state_t state;
} client_t;

client_state_t get_client_state(int fd);
client_t * new_client(int socket);
void destroy_client(int fd);
int get_paired_client_fd(int fd, client_t * client);
int register_client_by_socket(int socket);
int validate_secret(int sock_fd);
void accept_client();
int set_client_pty(client_t * client, int pty);
void open_terminal_and_exec_bash(char * ptyslave);
int init_socket();
int setup_pty(int * masterfd_p, char ** slavename_p);
void relay_bytes(int whence);
void epoll_loop(void);
int establish_client(int);
void handle_io_event(int fd);
int set_nonblocking(int fd);
int eager_write(int fd, const char * const str);

// epoll instance
int efd;

// main listening socket
int listen_fd;

// Kind of like a hash, or list of tuples
// At index i, the value is the associated client for FD i (pty || socket)
client_t * fd_client_map[MAX_CLIENTS * 2 + 5];


// Initialize resources and go into an accept() loop
// Each client is given a new thread -- which is inefficient
int main()
{
    tpool_init(handle_io_event);

    if ((efd = epoll_create1(EPOLL_CLOEXEC)) == -1)
    {
        perror("epoll creation failed");
        exit(EXIT_FAILURE);
    }

    if (init_socket() == -1)
    {
        exit(EXIT_FAILURE);
    }
    // Ignore exited children
    if (signal(SIGCHLD, SIG_IGN) == SIG_ERR)
    {
        perror("Failed to set SIGCHLD to SIG_IGN");
        exit(EXIT_FAILURE);
    }

    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
    {
        perror("Failed to set SIGPIPE to SIG_IGN");
        exit(EXIT_FAILURE);
    }

    epoll_loop();

    exit(EXIT_FAILURE);
}


// This is the epoll loop
// it waits, and then decides whether to relay data or close down a pair of resources
void epoll_loop()
{
    struct epoll_event evlist[MAX_CLIENTS * 2 + 1];
    int nevents;
    int i;

    while (1)
    {
        nevents = epoll_wait(efd, evlist, MAX_CLIENTS * 2, -1);
        for (i = 0; i < nevents; i++)
        {
            if (evlist[i].events & EPOLLIN)
            {
                tpool_add_task(evlist[i].data.fd);
            }
            else if (evlist[i].events & (EPOLLHUP | EPOLLRDHUP | EPOLLERR))
            {
                destroy_client(evlist[i].data.fd);
            }
        }
        // Error case
        if (nevents < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            else
            {
                perror("epoll wait");
                exit(EXIT_FAILURE);
            }
        }
    }
}

void handle_io_event(int fd)
{
    if (fd == listen_fd)
    {
        accept_client();
    }
    else if (get_client_state(fd) == secret)
    {
        if (validate_secret(fd) || establish_client(fd))
        {
            fprintf(stderr, "Error establishing client\n");
            destroy_client(fd);
        }
    }
    else
    {
        relay_bytes(fd);
    }
}

int validate_secret(int sock_fd)
{
    char * line;

    if ((line = readline(sock_fd)) == NULL)
    {
        perror("Error reading from client");
        return 1;
    }

    if (strcmp(SECRET, line))
    {
        fprintf(stderr, "Client gave incorrect protocol\n");
        eager_write(sock_fd, ERROR);
        return 1;
    }
    return 0;
}

int establish_client(int socket_fd)
{
    char * ptyslave;
    int ptymaster_fd;
    client_t * client = fd_client_map[socket_fd];

    if (setup_pty(&ptymaster_fd, &ptyslave))
    {
        close(socket_fd);
        pthread_exit(NULL);
    }

    set_nonblocking(socket_fd);
    set_nonblocking(ptymaster_fd);
    if (set_client_pty(client, ptymaster_fd))
    {
        return -1;
    }
    switch (fork())
    {
        case -1:
            perror("fork failed");
            return -1;
        case 0:
            close(ptymaster_fd);
            close(socket_fd);
            open_terminal_and_exec_bash(ptyslave);
            fprintf(stderr, "Failed to exec bash\n");
            exit(EXIT_FAILURE);
    }

    if (eager_write(socket_fd, OK))
    {
        return -1;
    }
    client->state = complete;
    free(ptyslave);
    printf("client established -- sock: %d  pty: %d\n", client->socket_fd, client->pty_fd);
    return 0;
}

int setup_pty(int * masterfd_p, char ** slavename_p)
{
    int master_fd;
    char * slavename;

    if ((master_fd = posix_openpt(O_RDWR | O_CLOEXEC)) == -1)
    {
        perror("openpt failed");
        return -1;
    }

    unlockpt(master_fd);
    slavename = (char *) malloc(1024);
    strcpy(slavename, ptsname(master_fd));

    *masterfd_p = master_fd;
    *slavename_p = slavename;
    return 0;
}

int init_socket()
{
    struct sockaddr_in addr;

    if ((listen_fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0)) == -1)
    {
        perror("Socket creation failed");
        return -1;
    }
    int i = 1;
    if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &i, sizeof(i)))
    {
        perror("setsockopt: SO_REUSEADDR");
        return -1;
    }
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(PORT);

    if (bind(listen_fd, (struct sockaddr *) &addr, sizeof addr) == -1)
    {
        perror("Bind failed");
        return -1;
    }

    if (listen(listen_fd, 512) == -1)
    {
        perror("Listen failed\n");
        return -1;
    }

    set_nonblocking(listen_fd);
    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = listen_fd;
    epoll_ctl(efd, EPOLL_CTL_ADD, listen_fd, &ev);

    return 0;
}

client_t * new_client(int socket)
{
    client_t * client = (client_t *) malloc(sizeof(client_t));

    client->socket_fd = socket;
    client->state = secret;
    client->pty_fd = -1; // not set yet
    return client;
}

int register_client_by_socket(int socket)
{
    struct epoll_event ev;
    client_t * client = new_client(socket);

    fd_client_map[socket] = client;

    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = socket;
    if (epoll_ctl(efd, EPOLL_CTL_ADD, socket, &ev) == -1)
    {
        perror("failed to add to epoll");
        return -1;
    }
    return 0;
}

int set_client_pty(client_t * client, int pty)
{
    struct epoll_event ev;

    client->pty_fd = pty;
    fd_client_map[pty] = client;

    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = pty;

    if (epoll_ctl(efd, EPOLL_CTL_ADD, pty, &ev) == -1)
    {
        // Remove the socket here, before closing the file itself
        epoll_ctl(efd, EPOLL_CTL_DEL, client->socket_fd, NULL);
        perror("failed to add to epoll");
        return -1;
    }

    return 0;
}

void accept_client()
{
    int client_fd;

    if ((client_fd = accept4(listen_fd, (struct sockaddr *) NULL, NULL, SOCK_CLOEXEC)) == -1)
    {
        perror("Socket accept failed");
        return;
    }
    if (client_fd >= 2 * MAX_CLIENTS + 5)
    {
        // Too many clients -- reject this one
        close(client_fd);
        return;
    }

    if (register_client_by_socket(client_fd) || eager_write(client_fd, REMBASH))
    {
        close(client_fd);
    }
}

void relay_bytes(int whence)
{
    char buff[BUFF_MAX];
    ssize_t nread;
    int total;
    int nwritten;

    client_t * client = fd_client_map[whence];
    int whither = get_paired_client_fd(whence, client);

    errno = 0;
    if ((nread = read(whence, buff, BUFF_MAX)) > 0)
    {
        total = 0;
        do
        {
            if ((nwritten = write(whither, buff + total, nread - total)) == -1)
            {
                break;
            }
            total += nwritten;
        }
        while (total < nread);
    }
    if (nread < 0 && errno != EWOULDBLOCK && errno != EAGAIN)
    {
        perror("Error reading");
        destroy_client(whence);
    }
    return;
}

void open_terminal_and_exec_bash(char * slavename)
{
    int slave_fd;

    if (setsid() == -1)
    {
        perror("setsid failed");
        return;
    }

    if ((slave_fd = open(slavename, O_RDWR)) == -1)
    {
        perror("Failed to open slave");
        return;
    }

    free(slavename);

    if ((dup2(slave_fd, STDIN_FILENO) == -1)
        || (dup2(slave_fd, STDOUT_FILENO) == -1)
        || (dup2(slave_fd, STDERR_FILENO) == -1))
    {
        perror("dup2 to either stdout, stdin, or stderr failed");
        return;
    }

    execlp("bash", "bash", NULL);
}

int eager_write(const int fd, const char * const msg)
{
    size_t accum = 0;
    size_t len = strlen(msg);
    int nwrote = 0;

    do
    {
        if ((nwrote = write(fd, msg + accum, len - accum)) == -1)
        {
            break;
        }
        accum += nwrote;
    }
    while (accum < len);

    return !(nwrote >= 0);
}

client_state_t get_client_state(int fd)
{
    return fd_client_map[fd]->state;
}

int get_paired_client_fd(int fd, client_t * client)
{
    return (fd == client->pty_fd ? client->socket_fd : client->pty_fd);
}

void unbind_fd(int fd)
{
    epoll_ctl(efd, EPOLL_CTL_DEL, fd, NULL);
    if (close(fd) != -1)
    {
        fd_client_map[fd] = NULL;
    }
}

void destroy_client(int fd)
{
    client_t * client = fd_client_map[fd];

    if (client == NULL)
    {
        close(fd);
        return;
    }
    int socket = client->socket_fd;
    int pty = client->pty_fd;

    unbind_fd(socket);

    if (client->state == complete)
    {
        unbind_fd(pty);
    }

    free(client);
}

// General purpose non-blockifier for file-descriptors
int set_nonblocking(int fd)
{
    int flags;

    if ((flags = fcntl(fd, F_GETFL, 0)) == -1)
    {
        perror("fcntl get flags");
        return -1;
    }
    flags |= O_NONBLOCK;
    if (fcntl(fd, F_SETFL, flags) == -1)
    {
        perror("fcntl set flags");
        return -1;
    }
    return 0;
}
