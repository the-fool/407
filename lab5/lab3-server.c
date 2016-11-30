#define _POSIX_C_SOURCE 200809L // for timers (librt)
#define _XOPEN_SOURCE   600 // for posix pty things
#define _GNU_SOURCE     // for science

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
#include <sys/syscall.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include "readline.c"
#include "tpool.h"

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
int setup_pty(int * masterfd_p, char ** slavename_p);
int safe_write(const int fd, char const * msg);
int safe_read(const int fd, char const * expected);
int eager_write(int fd, const char * const str, size_t len);
int relay_bytes(int whence, int whither);
int close_paired_fds(int fd);
void sigalrm_handler(int signal, siginfo_t * sip, void * ignore);
void * epoll_loop(void *);
void * handle_client(void * client_fd_ptr);
int register_client(int socket, int pty);
void open_terminal_and_exec_bash(char * ptyslave);
void relay_data(int whence);
// epoll instance
int efd;

// Kind of like a hash, or list of tuples
// At index i, the value is the associated FD for FD i (pty || socket)
int client_fd_pairs[MAX_CLIENTS * 2 + 5];

// Same idea -- map the exec'd subprocces PID to the FDs that relate to it
// If there is a socket connection at FD 15, then the 15th spot in this array
// holds the PID of the exec'd process associated with the socket
pid_t subprocess_by_fd[MAX_CLIENTS * 2 + 5];


// Initialize resources and go into an accept() loop
// Each client is given a new thread -- which is inefficient
int main()
{
    int server_listen_fd;
    int client_fd;
    int * client_fd_ptr;
    pthread_t thread_id;

    tpool_init(relay_data);

    if ((server_listen_fd = init_socket()) == -1)
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

    if ((efd = epoll_create1(EPOLL_CLOEXEC)) == -1)
    {
        perror("epoll creation failed");
        exit(EXIT_FAILURE);
    }

    if (pthread_create(&thread_id, NULL, &epoll_loop, NULL))
    {
        perror("Failed to create thread");
        exit(EXIT_FAILURE);
    }
    ;

    while (1)
    {
        if ((client_fd = accept4(server_listen_fd, (struct sockaddr *) NULL, NULL, SOCK_CLOEXEC)) == -1)
        {
            perror("Socket accept failed");
        }
        else if (client_fd >= 2 * MAX_CLIENTS + 5)
        {
            // Too many clients -- reject this one
            close(client_fd);
        }
        else
        {
            client_fd_ptr = (int *) malloc(sizeof(int));
            *client_fd_ptr = client_fd;
            if (pthread_create(&thread_id, NULL, &handle_client, client_fd_ptr))
            {
                perror("failed to create pthread");
                close(client_fd);
            }
        }
    }
    exit(EXIT_FAILURE);
}


// This is the epoll loop
// it waits, and then decides whether to relay data or close down a pair of resources
void * epoll_loop(void * _)
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
        printf("Epoll got %d events\n", nevents);
#endif
        for (i = 0; i < nevents; i++)
        {
            if (evlist[i].events & EPOLLIN)
            {
                if (relay_bytes(evlist[i].data.fd, client_fd_pairs[evlist[i].data.fd]))
                {
#ifdef DEBUG
                    printf("Unexpected IO error with client -- closing connection and terminating bash\n");
#endif
                    // kill bash subprocess
                    kill(subprocess_by_fd[evlist[i].data.fd], SIGTERM);
                    close_paired_fds(evlist[i].data.fd);
                }
            }
            else if (evlist[i].events & (EPOLLHUP | EPOLLERR))
            {
#ifdef DEBUG
                printf("Recd EPOLLHUP or EPOLLERR on %d -- closing it and %d\n", evlist[i].data.fd, client_fd_pairs[evlist[i].data.fd]);
#endif
                close_paired_fds(evlist[i].data.fd);
            }
        }
    }
}

int close_paired_fds(int fd)
{
    return close(fd) || close(client_fd_pairs[fd]);
}

// Protocol handshake, setup of PTY, store client description in global register, fork
void * handle_client(void * client_fd_ptr)
{
    char * ptyslave;
    int ptymaster_fd;

    struct epoll_event ev[2];
    pid_t subproc;

    int socket_fd = *(int *) client_fd_ptr;

    free(client_fd_ptr);

    pthread_detach(pthread_self());

    if (handshake_protocol(socket_fd))
    {
        perror("Client failed protocol exchange");
        close(socket_fd);
        pthread_exit(NULL);
    }


    if (setup_pty(&ptymaster_fd, &ptyslave))
    {
        close(socket_fd);
        pthread_exit(NULL);
    }

    set_nonblocking(socket_fd);
    set_nonblocking(ptymaster_fd);

    switch (subproc = fork())
    {
        case -1:
            perror("fork failed");
            exit(EXIT_FAILURE);
        case 0:
            close(ptymaster_fd);
            open_terminal_and_exec_bash(ptyslave);
            exit(EXIT_FAILURE);
    }
    free(ptyslave);
    // Special global registers for client description
    // The subprocess PID is redundant so that it can be found based on either socket or pty
    client_fd_pairs[socket_fd] = ptymaster_fd;
    client_fd_pairs[ptymaster_fd] = socket_fd;
    subprocess_by_fd[socket_fd] = subproc;
    subprocess_by_fd[ptymaster_fd] = subproc;

    ev[0].data.fd = socket_fd;
    ev[1].data.fd = ptymaster_fd;
    ev[0].events = EPOLLIN | EPOLLET;
    ev[1].events = EPOLLIN | EPOLLET;
    epoll_ctl(efd, EPOLL_CTL_ADD, socket_fd, ev);
    epoll_ctl(efd, EPOLL_CTL_ADD, ptymaster_fd, ev + 1);

    return NULL;
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
    int fd;
    struct sockaddr_in addr;

    if ((fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0)) == -1)
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
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(PORT);

    if (bind(fd, (struct sockaddr *) &addr, sizeof addr) == -1)
    {
        perror("Bind failed");
        return -1;
    }

    if (listen(fd, 512) == -1)
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

    // does not handle malicious clients!
    // better would be a rotation through readable files, rather
    // than being patient with a greedy client
    while ((nread = read(whence, buff, BUFF_MAX)) > 0)
    {
        if (eager_write(whither, buff, nread) == -1)
        {
            perror("Failed writing");
            break;
        }
    }
    if (nread == -1 && errno != EWOULDBLOCK && errno != EAGAIN)
    {
        perror("Error reading");
        return -1;
    }
    return 0;
}

void open_terminal_and_exec_bash(char * ptyslave)
{
    int slave_fd;

    if (setsid() == -1)
    {
        perror("setsid failed");
        exit(EXIT_FAILURE);
    }

    if ((slave_fd = open(ptyslave, O_RDWR)) == -1)
    {
        perror("Failed to open slave");
        exit(EXIT_FAILURE);
    }
    free(ptyslave);
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

void sigalrm_handler(int signal, siginfo_t * sip, void * ignore)
{

#ifdef DEBUG
    printf("caught alarm, with value: %d\n", *(int *) (sip->si_ptr));
#endif
    // set the flag to flown, which will be used in the handshake routine
    // to determine failure.
    // Most likely, though, the alarm will cause a blocked read() call to be errored with EINTR
    *(int *) sip->si_ptr = 1;
}
int handshake_protocol(int fd)
{
    // 3 second timer
    static struct itimerspec timer = { .it_value = { .tv_sec = 3 } };
    struct sigaction sa = { .sa_flags = SA_SIGINFO, .sa_sigaction = &sigalrm_handler };
    struct sigevent sev = { .sigev_signo = SIGALRM, .sigev_notify = SIGEV_THREAD_ID };
    int alarmed_flag = 0;
    timer_t timerid;

    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGALRM, &sa, NULL) == -1)
    {
        perror("Setting up sigaction");
    }

    // Setup sigevent to contain our alarmed_flag for data,
    // and to be thread-specific
    sev.sigev_value.sival_ptr = &alarmed_flag;
    sev._sigev_un._tid = syscall(__NR_gettid);

    if (timer_create(CLOCK_REALTIME, &sev, &timerid) == -1)
    {
        perror("timer create");
    }
    if (timer_settime(timerid, 0, &timer, NULL) == -1)
    {
        perror("settime");
    }
    // alarmed_flag is set in the sigalrm handler
    // it is checked before every stage of the handshake to avoid race conditions
    if (alarmed_flag || safe_write(fd, REMBASH) ||
        alarmed_flag || safe_read(fd, SECRET) ||
        alarmed_flag || safe_write(fd, OK))
    {
        return 1;
    }

    if (signal(SIGALRM, SIG_IGN) == SIG_ERR)
    {
        perror("setting sigalrm to sig_ign -- continuing");
    }
    if (timer_delete(timerid) == -1)
    {
        perror("timer_delete");
    }
    // Success
    return 0;
}

int safe_write(const int fd, char const * str)
{
    if (eager_write(fd, str, strlen(str)) == -1)
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
        perror("Error reading from client");
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
    size_t accum = 0;
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
    accum = 0;
    nwrote = 0;
    return nwrote;
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
