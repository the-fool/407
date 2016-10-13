#define _POSIX_C_SOURCE 199309L
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
#include <time.h>
#include <unistd.h>

#include "readline.c"

#define BUFF_MAX    4 * 1024
#define MAX_EVENTS  16
#define MAX_CLIENTS 64 * 1000
#define PORT        4070
#define SECRET      "<cs407rembash>\n"
#define REMBASH     "<rembash>\n"
#define OK          "<ok>\n"
#define ERROR       "<error>\n"

int init_socket();
int set_nonblocking(int fd);
int handshake_protocol(int connect_fd);
int safe_write(const int fd, char const * msg);
int safe_read(const int fd, char const * expected);
int sigchld_to_sig_ign();
int eager_write(int fd, const char * const msg, size_t len);
int relay_bytes(int whence, int whither);
void * io_loop(void *);
void * handle_client(void * client_fd_ptr);
void debug(int fd);
void open_terminal_and_exec_bash(char * ptyslave);

int efd;
int client_fd_pairs[MAX_CLIENTS * 2 + 5];

int main()
{
    int server_socket_fd;
    int client_fd;
    int * client_fd_ptr;
    pthread_t thread_id;

    if ((server_socket_fd = init_socket()) == -1)
    {
        exit(EXIT_FAILURE);
    }
    // Ignore exited children
    sigchld_to_sig_ign();

    if ((efd = epoll_create1(EPOLL_CLOEXEC)) == -1)
    {
        perror("epoll creation failed");
        exit(EXIT_FAILURE);
    }
    pthread_create(&thread_id, NULL, &io_loop, NULL);
    while (1)
    {
#ifdef DEBUG
        printf("Server is waiting\n");
#endif
        if ((client_fd = accept4(server_socket_fd, (struct sockaddr *) NULL, NULL, SOCK_CLOEXEC)) == -1)
        {
            perror("Socket accept failed");
        }
        else
        {
#ifdef DEBUG
            printf("Received client\n");
#endif
            client_fd_ptr = (int *) malloc(sizeof(int));
            *client_fd_ptr = client_fd;
            if (pthread_create(&thread_id, NULL, &handle_client, client_fd_ptr))
            {
                perror("failed to create pthread");
            }
        }
    }
}

int set_nonblocking(int sfd)
{
    int flags;

    if ((flags = fcntl(sfd, F_GETFL, 0)) == -1) {
      perror("fcntl get flags");
      return -1;
    }
    flags |= O_NONBLOCK;
    if (fcntl(sfd, F_SETFL, flags) == -1) {
      perror("fcntl set flags");
      return -1;
    }
    return 0;
}
void * io_loop(void * _)
{
    struct epoll_event evlist[MAX_EVENTS];
    int nevents;
    int i;

    while (1)
    {
        nevents = epoll_wait(efd, evlist, MAX_EVENTS, -1);
        if (nevents == -1)
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
        #ifdef DEBUG
        printf("Recd %d events\n", nevents);
        #endif
        for (i = 0; i < nevents; i++)
        {
            if (evlist[i].events & EPOLLIN)
            {
                if (relay_bytes(evlist[i].data.fd, client_fd_pairs[evlist[i].data.fd])) {
                  // TODO -- kill bash subprocess
                }
            }
            else if (evlist[i].events & (EPOLLHUP | EPOLLERR))
            {
              #ifdef DEBUG
                printf("Recd EPOLLHUP or EPOLLERR on %d -- closing it and %d\n", evlist[i].data.fd, client_fd_pairs[evlist[i].data.fd]);
              #endif
                close(client_fd_pairs[evlist[i].data.fd]);
                close(evlist[i].data.fd);
            }
        }
    }
}

void * handle_client(void * client_fd_ptr)
{
    static char * ptyslave;
    static struct epoll_event ev[2];
    static int ptymaster_fd;

    int socket_fd = *(int *) client_fd_ptr;

    free(client_fd_ptr);


    if (handshake_protocol(socket_fd))
    {
        perror("Client failed protocol exchange");
        exit(EXIT_FAILURE);
    }
    set_nonblocking(socket_fd);
    if ((ptymaster_fd = posix_openpt(O_RDWR | O_CLOEXEC)) == -1)
    {
        perror("openpt failed");
        exit(EXIT_FAILURE);
    }
    set_nonblocking(ptymaster_fd);
    unlockpt(ptymaster_fd);
    ptyslave = (char *) malloc(1024); // malloc first, to avoid race condition
    strcpy(ptyslave, ptsname(ptymaster_fd));

    switch (fork())
    {
        case -1:
            perror("fork failed");
            exit(EXIT_FAILURE);
        case 0:
            close(ptymaster_fd);
            open_terminal_and_exec_bash(ptyslave);
            exit(EXIT_FAILURE);
    }
    client_fd_pairs[socket_fd] = ptymaster_fd;
    client_fd_pairs[ptymaster_fd] = socket_fd;

    ev[0].data.fd = socket_fd;
    ev[1].data.fd = ptymaster_fd;
    ev[0].events = EPOLLIN | EPOLLET;
    ev[1].events = EPOLLIN | EPOLLET;
    epoll_ctl(efd, EPOLL_CTL_ADD, socket_fd, ev);
    epoll_ctl(efd, EPOLL_CTL_ADD, ptymaster_fd, ev + 1);

    return NULL;
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


int relay_bytes(int whence, int whither)
{
    static char buff[BUFF_MAX];
    static ssize_t nread;

    #ifdef DEBUG
    printf("Relaying from %d to %d\n", whence, whither);
    #endif
    // does not handle malicious clients!
    while ((nread = read(whence, buff, BUFF_MAX)) > 0)
    {
        if (eager_write(whither, buff, nread) == -1)
        {
            perror("Failed writing");
            break;
        }
    }
    if (nread == -1 && errno != EWOULDBLOCK && errno != EAGAIN) {
      perror("Error reading");
      return -1;
    }
    return 0;
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
    static struct sigevent sev;
    static struct itimerspec timer;
    timer.it_value.tv_nsec = 2000000000; // 2 seconds in nanoseconds
    timer_t timerid;

    sev.sigev_signo = SIGALRM;
    sev.sigev_notify = SIGEV_THREAD_ID;
    sev.sigev_value.sival_ptr = &timerid;
    sev._sigev_un._tid = pthread_self();

    timer_create(CLOCK_REALTIME, &sev, &timerid);
    timer_settime(timerid, 0, &timer, NULL);
    if (safe_write(fd, REMBASH) ||
        safe_read(fd, SECRET) ||
        safe_write(fd, OK))
    {
        return 1;
    }
    else
    {
        timer_delete(timerid);
        return 0;
    }
}

int safe_write(const int fd, char const * str)
{
    if (write(fd, str, strlen(str)) == -1)
    {
        perror("Failed to write");
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
