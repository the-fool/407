#define _POSIX_C_SOURCE 200809L // for timers (librt)
#define _XOPEN_SOURCE 600  // for posix pty things
#define _GNU_SOURCE // for science

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
int eager_write(int fd, const char * const str, size_t len);
int relay_bytes(int whence, int whither);
int close_paired_fds(int fd);
void sigalrm_handler(int signal, siginfo_t *sip, void *ignore);
void * io_loop(void *);
void * handle_client(void * client_fd_ptr);
void debug(int fd);
void open_terminal_and_exec_bash(char * ptyslave);

// epoll instance
int efd;

// Kind of like a hash, or list of tuples
// At index i, the value is the associated FD for FD i (pty || socket)
int client_fd_pairs[MAX_CLIENTS * 2 + 5];

// Same idea -- map the exec'd subprocces PID to the FDs that relate to it
// If there is a socket connection at FD 15, then the 15th spot in this array
// holds the PID of the exec'd process associated with the socket
pid_t subprocess_by_fd[MAX_CLIENTS * 2 + 5];

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
    if (signal(SIGCHLD, SIG_IGN) == SIG_ERR)
    {
        perror("Failed to set SIGCHLD to SIG_IGN");
        exit(EXIT_FAILURE);
    }

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
        printf("Epoll got %d events\n", nevents);
#endif
        for (i = 0; i < nevents; i++)
        {
            if (evlist[i].events & EPOLLIN)
            {
                if (relay_bytes(evlist[i].data.fd, client_fd_pairs[evlist[i].data.fd])) {
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

int close_paired_fds(int fd) {
  return close(fd) || close(client_fd_pairs[fd]);
}

void * handle_client(void * client_fd_ptr)
{
    char * ptyslave;
    struct epoll_event ev[2];
    int ptymaster_fd;
    pid_t subproc;

    int socket_fd = *(int *) client_fd_ptr;

    free(client_fd_ptr);

    if (handshake_protocol(socket_fd))
    {
        perror("Client failed protocol exchange");
        close(socket_fd);
        return NULL;
    }
    set_nonblocking(socket_fd);
    if ((ptymaster_fd = posix_openpt(O_RDWR | O_CLOEXEC)) == -1)
    {
        perror("openpt failed");
        close(socket_fd);
        return NULL;
    }
    set_nonblocking(ptymaster_fd);
    unlockpt(ptymaster_fd);
    ptyslave = (char *) malloc(1024); // malloc first, to avoid race condition
    strcpy(ptyslave, ptsname(ptymaster_fd));

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
    // does not handle malicious clients!
    // better would be a rotation through readable files, rather
    // than staying with a potential hog
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

void sigalrm_handler(int signal, siginfo_t *sip, void *ignore) {

#ifdef DEBUG
  printf("caught alarm, with value: %d\n", *(int *)(sip->si_ptr));
#endif
  // set the flag to flown, which will be used in the handshake routine
  // to determine failure.
  // Most likely, though, a blocked read() call will get errored with EINTR
  *(int*)sip->si_ptr = 1;
}
int handshake_protocol(int fd)
{
    static struct itimerspec timer = {.it_value = {.tv_sec = 3}};
    static struct sigaction sa = {.sa_flags=SA_SIGINFO};
    struct sigevent sev = {.sigev_signo=SIGALRM, .sigev_notify=SIGEV_THREAD_ID};
    int alarmed_flag = 0;
    timer_t timerid;

    sa.sa_sigaction = &sigalrm_handler;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGALRM, &sa, NULL) == -1) {
      perror("Setting up sigaction");
    }

    sev.sigev_value.sival_ptr = &alarmed_flag;
    sev._sigev_un._tid = syscall(__NR_gettid);

    if (timer_create(CLOCK_REALTIME, &sev, &timerid) == -1) {
      perror("timer create");
    }
    if (timer_settime(timerid, 0, &timer, NULL) == -1) {
      perror("settime");
    }
    if (alarmed_flag || safe_write(fd, REMBASH) ||
        alarmed_flag || safe_read(fd, SECRET) ||
        alarmed_flag || safe_write(fd, OK))
    {
        return 1;
    }
    else
    {
        if (signal(SIGALRM, SIG_IGN) == SIG_ERR) {
          perror("setting sigalrm to sig_ign -- continuing");
          // so what?  moving right along . . .
        }
        timer_delete(timerid);
        return 0;
    }
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
