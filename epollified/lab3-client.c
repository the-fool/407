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
#include <termios.h>
#include <unistd.h>
#include "readline.c"

#define PORT     4070
#define SECRET   "<cs407rembash>\n"
#define BUFF_MAX 4096
#define REMBASH  "<rembash>\n"
#define OK       "<ok>\n"

int safe_write(const char * const message);
int safe_read(char const * expected);
int eager_write(int fd, const char * const msg, size_t len);
void handle_io();
void read_socket_write_terminal();
void read_terminal_write_socket();
void connect_to_server(char * host);
void run_protocol();
void stash_termios(struct termios * ttyp);
void reset_termios_attrs(struct termios * ttyp);
void set_stdin_termios_attrs();
void handle_sigchld(int, siginfo_t *, void *);

int SERVER_FD; // Global socket file-descriptor, for convenience
struct termios stashed_termios_attr; // global terminal settings

int main(int argc, char ** argv)
{
    if (argc != 2)
    {
        printf("Usage: client HOST_IP");
        exit(EXIT_FAILURE);
    }

    connect_to_server(argv[1]);

  #ifdef DEBUG
    printf("Connected\n");
  #endif

    run_protocol();

    stash_termios(&stashed_termios_attr);
    set_stdin_termios_attrs();

    handle_io();

    if (close(SERVER_FD) == -1)
    {
        perror("Failed to close socket");
        exit(EXIT_FAILURE);
    }
    reset_termios_attrs(&stashed_termios_attr);
    exit(errno);
}


void reset_termios_attrs(struct termios * ttyp)
{
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, ttyp) == -1)
    {
        perror("Set tty attributes failed");
        exit(EXIT_FAILURE);
    }
}

void stash_termios(struct termios * ttyp)
{
    if (!isatty(STDIN_FILENO))
    {
        fprintf(stderr, "Stdin must be a terminal. Exiting.\n");
        exit(EXIT_FAILURE);
    }
    if (tcgetattr(STDIN_FILENO, ttyp) == -1)
    {
        perror("Failed to get tty attributes");
        exit(EXIT_FAILURE);
    }
}

void set_stdin_termios_attrs()
{
    struct termios attr;

    if (tcgetattr(STDIN_FILENO, &attr) == -1)
    {
        perror("Failed getting tty attributes");
        exit(EXIT_FAILURE);
    }
    attr.c_lflag &= ~(ICANON | ECHO );
    attr.c_cc[VMIN] = 1;
    attr.c_cc[VTIME] = 0;
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &attr) == -1)
    {
        perror("Failed setting tty attributes");
        exit(EXIT_FAILURE);
    }
}


void connect_to_server(char * host)
{
    struct sockaddr_in socket_address;
    char error_string[128];

    SERVER_FD = socket(AF_INET, SOCK_STREAM, 0);
    if (SERVER_FD == -1)
    {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }
    inet_aton(host, &socket_address.sin_addr);
    socket_address.sin_family = AF_INET;
    socket_address.sin_port = htons(PORT);

    if (connect(SERVER_FD, (struct sockaddr *) &socket_address, sizeof socket_address) == -1)
    {
        sprintf(error_string, "Unable to connect to %s:%d", host, PORT);
        perror(error_string);
        exit(EXIT_FAILURE);
    }
}

void run_protocol()
{
    if (safe_read(REMBASH) ||
        safe_write(SECRET) ||
        safe_read(OK))
    {
        fprintf(stderr, "Protocol failed. Exiting.\n");
        exit(EXIT_FAILURE);
    }
}

void handle_io()
{
    int child_pid;
    struct sigaction sa;

    sa.sa_sigaction = &handle_sigchld;
    sa.sa_flags = SA_SIGINFO | SA_RESTART | SA_NOCLDSTOP;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGCHLD, &sa, 0) == -1)
    {
        perror("Unable to setup sigaction");
        exit(EXIT_FAILURE);
    }

    switch (child_pid = fork())
    {
        case -1:
            perror("fork failed");
            exit(EXIT_FAILURE);
        case 0:
            read_terminal_write_socket();
            exit(EXIT_FAILURE);
    }

    read_socket_write_terminal();

    sa.sa_handler = SIG_IGN;
    if (sigaction(SIGCHLD, &sa, 0) == -1)
    {
        perror("Unable to setup sigaction");
    }
    if (kill(child_pid, 9) == -1)
    {
        perror("Kill() failed");
    }
}

void read_socket_write_terminal()
{
    char buff[BUFF_MAX];
    int nread;

    while ((nread = read(SERVER_FD, buff, BUFF_MAX)) > 0)
    {
        if (eager_write(STDOUT_FILENO, buff, (size_t) nread) == -1)
        {
            break;
        }
    }
    if (errno)
    {
        perror("Error reading from socket and/or writing to stdout");
    }
}

void read_terminal_write_socket()
{
    char buff[BUFF_MAX];
    int nread;

    while ((nread = read(STDIN_FILENO, buff, BUFF_MAX)) > 0)
    {
        if (eager_write(SERVER_FD, buff, (size_t) nread) == -1)
        {
            break;
        }
    }
    #ifdef DEBUG
    printf("Client exiting loop\n");
    #endif
    if (errno)
    {
        perror("I/O error reading from terminal and/or writing to socket");
    }
    else
    {
        fprintf(stderr, "Connection to server broken unexpectedly");
    }
}

int safe_write(const char * const message)
{
    if (eager_write(SERVER_FD, message, strlen(message)) == -1)
    {
        perror("Failed to write\n");
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

int safe_read(char const * expected)
{
    char * line;

    if ((line = readline(SERVER_FD)) == NULL)
    {
        fprintf(stderr, "Error reading from server\n");
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

void handle_sigchld(int signo, siginfo_t * info, void * context)
{
    int status;
    int exit_code;

    if (waitpid((pid_t) (-1), &status, WNOHANG) > 0)
    {
        // collected child
        reset_termios_attrs(&stashed_termios_attr);
        exit_code = !(WIFEXITED(status) && !WEXITSTATUS(status));
      #ifdef DEBUG
        printf("Exiting: %d\n", exit_code);
      #endif
        exit(exit_code);
    }
}
