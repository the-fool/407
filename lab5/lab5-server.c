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
#define MAX_CLIENTS 64 * 1000
#define PORT        4070
#define SECRET      "<cs407rembash>\n"
#define REMBASH     "<rembash>\n"
#define OK          "<ok>\n"
#define ERROR       "<error>\n"

typedef enum handshake_state
{
    init,
    wait_for_secret,
    complete
} handshake_state_t;

typedef struct client
{
    int socket_fd;
    int pty_fd;
    handshake_state_t state;
} client_t;

int init_socket();
int set_nonblocking(int fd);
int handshake_protocol(int connect_fd);
int setup_pty(int * masterfd_p, char ** slavename_p);
int safe_write(const int fd, char const * msg);
int safe_read(const int fd, char const * expected);
int eager_write(int fd, const char * const str, size_t len);
void relay_bytes(int whence);
void destroy_client(int fd);
void sigalrm_handler(int signal, siginfo_t * sip, void * ignore);
void * epoll_loop(void *);
void * handle_client(void * client_fd_ptr);
int register_client(int socket, int pty);
void open_terminal_and_exec_bash(char * ptyslave);
void handle_io_event(int fd);
void accept_client();
// epoll instance
int efd;

// main listening socket
int listen_fd;
// Kind of like a hash, or list of tuples
// At index i, the value is the associated FD for FD i (pty || socket)
int client_fd_pairs[MAX_CLIENTS * 2 + 5];

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

    epoll_loop(NULL);

    exit(EXIT_FAILURE);
}


// This is the epoll loop
// it waits, and then decides whether to relay data or close down a pair of resources
void * epoll_loop(void * _)
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


void destroy_client(int fd_1)
{
    int fd_2 = client_fd_pairs[fd_1];

    epoll_ctl(efd, EPOLL_CTL_DEL, fd_1, NULL);
    epoll_ctl(efd, EPOLL_CTL_DEL, fd_2, NULL);

    close(fd_1);
    close(fd_2);
}

// Protocol handshake, setup of PTY, store client description in global register, fork
void * handle_client(void * client_fd_ptr)
{
    char * ptyslave;
    int ptymaster_fd;

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

    switch (fork())
    {
        case -1:
            perror("fork failed");
            close(socket_fd);
            pthread_exit(NULL);
        case 0:
            close(ptymaster_fd);
            close(socket_fd);
            open_terminal_and_exec_bash(ptyslave);
            exit(EXIT_FAILURE);
    }

    free(ptyslave);
    if (register_client(socket_fd, ptymaster_fd))
    {
        close(socket_fd);
        close(ptymaster_fd);
        pthread_exit(NULL);
    }

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
    // Add the socket fd to the epoll list
    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = listen_fd;
    epoll_ctl(efd, EPOLL_CTL_ADD, listen_fd, &ev);

    return 0;
}

int register_client(int socket, int pty)
{
    struct epoll_event ev;

    client_fd_pairs[socket] = pty;
    client_fd_pairs[pty] = socket;

    // Add the two argument FDs to be epolled for input:
    // Note that if adding fails, this may be due simply to premature
    // closure of client connection causing FDs to already be closed:
    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = socket;
    if (epoll_ctl(efd, EPOLL_CTL_ADD, socket, &ev) == -1)
    {
        perror("failed to add to epoll");
        return -1;
    }
    ev.data.fd = pty;
    if (epoll_ctl(efd, EPOLL_CTL_ADD, pty, &ev) == -1)
    {
        // Remove the socket here, before closing the file itself
        epoll_ctl(efd, EPOLL_CTL_DEL, socket, NULL);
        perror("failed to add to epoll");
        return -1;
    }

    return 0;
}

void accept_client() {
  int client_fd;
  int * client_fd_ptr;
  pthread_t thread_id;
  if ((client_fd = accept4(listen_fd, (struct sockaddr *) NULL, NULL, SOCK_CLOEXEC)) == -1)
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

void handle_io_event(int fd) {
  if (fd == listen_fd) {
    accept_client();
  } else {
    relay_bytes(fd);
  }
}

void relay_bytes(int whence)
{
    char buff[BUFF_MAX];
    ssize_t nread;
    int total;
    int nwritten;
    int whither = client_fd_pairs[whence];

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
    perror("Failed to exec bash");
}

void sigalrm_handler(int signal, siginfo_t * sip, void * ignore)
{
    printf("caught alarm, with value: %d\n", *(int *) (sip->si_ptr));
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
