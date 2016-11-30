// Server Solution to Lab #3 in CS 407/591, Fall 2016.
// Author: Norman Carver (copyright 2016), Computer Science Dept., Southern Illinois University Carbondale.
// This material is provided for personal use by students enrolled in CS407/591 Fall 2016 only!
// Any other use represents infringement of the author's exclusive rights under US copyright law.
// In particular, posting this file to a website or in any way sharing it is expressly forbidden.
// Such sharing is also a violation of SIUC's Student Conduct Code (section 2.1.3), so may result
// in academic sanctions such as grade reduction.
//
// Usage: server
//
// Properties:
// -- parallel/concurrent server (can handle multiple simultaneous clients)
// -- uses multiplexed I/O with epoll to handle all client data transfers
// -- server uses two permanent threads:
//      (1) main server loop that accepts new clients
//      (2) epoll loop and data transfers for all clients
// -- creates an additional temporary thread for each client to run handle_client()
//    (pthread_attr has these threads created detached to avoid threads memory leak)
// -- creates one subprocess for each client:
//      (1) exec bash with standard in/out/error redirected to PTY
// -- creates a PTY for bash-client interaction (stdin/stout/stderr redirected to PTY)
// -- puts each bash subprocess into separate session, to allow concurrent bash processes
// -- sets SIGCHLD to be ignored to avoid having to collect bash subprocesses
// -- sets SIGPIPE to be ignored to ensure write() to closed socket does not terminate server
// -- handles partial socket write's, but uses write() loop that can block server until data fully written
// -- broken/malicious clients cannot cause resource problems because timer will disconnect them
// -- single subprocess/client is best can do for this remote shell server
// -- uses *_CLOEXEC options to socket(), epoll_create1(), accept4(), and fcntl() to
//      set close-on-exec options for listening socket, client sockets, epoll unit,
//      and PTY masters, so their FDs are not inherited by the bash processes, since
//      not only is this a security issue, it can cause a client's connection to not close.


#define _XOPEN_SOURCE 600  //For posix_openpt(), etc.
#define _GNU_SOURCE  //For syscall(), accept4()
#define _POSIX_C_SOURCE 199309L  //For timer_create()

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <wait.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/syscall.h>

#include "tpool.h"

//Declared constants:
#define PORTNUM 4070
#define SECRET "<cs407rembash>\n"
#define MAX_NUMBER_CLIENTS 1000


//Function prototypes:
int setup_listening_socket();
void *handle_client_setup(void *client_fd_ptr);
int validate_client_secret(int client_fd);
void timer_handler(int sig);
int create_pty_pair(int *ptymasterfd_ptr, char **ptyslavename_ptr);
void exec_bash_via_pty(char *ptyslave_name);
int add_client(int sock_fd, int ptymaster_fd);
void remove_client(int client_fd);
void *epoll_and_transfer_data(void *ignore);
void relay_data_between_fds(int sourcefd, int targetfd);
void print_id_info(char *message);
void relay_data(int sourcefd);

//Global variables (accessible from all threads):
//FD for epoll unit:
int epoll_fd;

//Table of client FD mappings: PTY master FD <--> client socket FD:
//(fd_client_mapping[FD] gives other client pair for FD)
int fd_client_mapping[2 * MAX_NUMBER_CLIENTS + 5];  //+5 for 0,1,2, listen-socket FD, epoll FD



int main()
{
  #ifdef DEBUG
  print_id_info("Server starting: ");
  #endif

  int listen_fd, connect_fd;
  pthread_t threadid;

  // init tpool
  tpool_init(relay_data);

  //Create listening TCP socket:
  if ((listen_fd = setup_listening_socket()) == -1)
    exit(EXIT_FAILURE);

  //Create an epoll unit (in global variable):
  //(Using epoll_create1() for EPOLL_CLOEXEC to keep epoll unit FD
  //from being open in bash subprocesses, avoids need for fcntl() call.)
  if ((epoll_fd = epoll_create1(EPOLL_CLOEXEC)) == -1) {
    perror("Server: failed to create epoll unit");
    exit(EXIT_FAILURE); }

  //Create new thread to transfer data between PTYs and sockets, using epoll:
  if (pthread_create(&threadid,NULL,epoll_and_transfer_data,NULL) != 0) {
    perror("Server: failed to create thread to run epoll()");
    exit(EXIT_FAILURE); }

  //Set SIGCHLD signals to be ignored, which causes child process
  //results to be automatically discarded when they terminate:
  //(This will avoid need to collect subprocesses running bash.)
  signal(SIGCHLD,SIG_IGN);

  //Set SIGPIPE signals to be ignored, so that write to closed connection
  //produces error return, rather than signal-based termination:
  signal(SIGPIPE,SIG_IGN);

  //Setup handler for timer SIGALRM signals when doing initial protocol exchange:
  struct sigaction sa;
  memset(&sa,0,sizeof(sa));
  sa.sa_flags = 0;
  sa.sa_handler = timer_handler;
  sigaction(SIGALRM,&sa,NULL);

  //Create a pthreads attribute object so handle-client threads start detached:
  pthread_attr_t pthread_attr;
  if (pthread_attr_init(&pthread_attr) != 0 || pthread_attr_setdetachstate(&pthread_attr,PTHREAD_CREATE_DETACHED) != 0) {
    perror("Server: failed to create pthreads attribute object");
    exit(EXIT_FAILURE); }

  //Main server loop to wait for a new connection request and create
  //a new thread to handle initial connection, with server continuing forever:
  while(1) {
    //Accept a new connection and get socket to use for client:
    //(Using Linux-specific accept4() for SOCK_CLOEXEC to keep client socket FDs
    //from being open in bash subprocesses, avoids need for fcntl() call.)
    if ((connect_fd = accept4(listen_fd,(struct sockaddr*)NULL,NULL,SOCK_CLOEXEC)) != -1) {
      //Check that not out of space to handle:
      if (connect_fd >= 2 * MAX_NUMBER_CLIENTS + 5) {
	  close(connect_fd);
	  break; }
      //Create thread to handle setup of new client connection:
       int *connect_fd_ptr = (int*)malloc(sizeof(int));
       *connect_fd_ptr = connect_fd;
      if (pthread_create(&threadid,&pthread_attr,handle_client_setup,connect_fd_ptr) != 0) {
        perror("Server: failed to create thread to handle new client");
        close(connect_fd); } }  //Pthread creation failure: close client only!
  }

  //Should never end up here, but just in case:
  return EXIT_FAILURE;
}



// Function to setup listening TCP server socket.
// Returns listening socket FD, else -1 on error.
int setup_listening_socket()
{
  int listen_fd;
  struct sockaddr_in servaddr;

  //Create socket for server to listen on:
  //(Using Linux-specific SOCK_CLOEXEC option to keep listening socket FD
  //from being open in bash subprocesses, avoids need for fcntl() call.)
  if ((listen_fd = socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0)) == -1) {
    perror("Server: socket call failed");
    return -1; }

  //Set up socket so port can be immediately reused:
  int i=1;
  setsockopt(listen_fd,SOL_SOCKET,SO_REUSEADDR,&i,sizeof(i));

  //Set up server address struct:
  memset(&servaddr,0,sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_port = htons(PORTNUM);
  servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  //As an alternative for setting up address, could have had for declaration:
  //struct sockaddr_in servaddr = {AF_INET,htons(PORTNUM),htonl(INADDR_ANY)};

  //Give socket a name/address by binding to a port:
  if (bind(listen_fd,(struct sockaddr *)&servaddr,sizeof(servaddr)) == -1) {
    perror("Server: bind call failed");
    return -1; }

  //Start socket listening:
  if (listen(listen_fd,128) == -1) {
    perror("Server: listen call failed");
    return -1; }

  return listen_fd;
}



// Function to handle a new client connection:
//  (1) carries out the initial rembash protocol exhange;
//  (2) creates PTY;
//  (3) creates a subprocess in which to run bash, redirecting standard in/out/error to PTY;
// Runs in a new temporary pthread for each client; exits after above steps.
// Note that because a client connection could close at any time, socket read/write errors
// simply stop further handling of the client--they do not cause server termination.
void *handle_client_setup(void *client_fd_ptr)
{
  const char * const server1 = "<rembash>\n";
  const char * const server2ok = "<ok>\n";
  const char * const server2err = "<error>\n";

  char *ptyslave_name;
  int ptymaster_fd;

  //Recover client_fd:
  int client_fd =  *(int*)client_fd_ptr;
  free(client_fd_ptr);

  #ifdef DEBUG
  printf("Starting protocol exchange for new client (FD %d)\n",client_fd);
  #endif

  //Write initial protocol ID to client:
  if (write(client_fd,server1,strlen(server1)) == -1) {
    #ifdef DEBUG
    printf("Error writing protocol ID to client (FD %d)\n",client_fd);
    #endif
    close(client_fd);
    pthread_exit(NULL); }

  if (!validate_client_secret(client_fd)) {
    write(client_fd,server2err,strlen(server2err));
    close(client_fd);
    pthread_exit(NULL); }

  if (!create_pty_pair(&ptymaster_fd,&ptyslave_name)) {
    #ifdef DEBUG
    printf("Failed to create PTY pair for client (FD %d)\n",client_fd);
    #endif
    close(client_fd);
    pthread_exit(NULL); }

  //Make child process to run bash in:
  switch (fork()) {
  case -1:  //fork error:
    perror("Server: fork call to create bash subprocess failed");
    //Will not be able to run bash for this client, so terminate client:
    //(Merely exit this client-handling thread, so server and existing clients will continue.)
    close(client_fd);
    pthread_exit(NULL);

  case 0:  //CHILD process:

    #ifdef DEBUG
    print_id_info("New subprocess for bash (pre setsid): ");
    #endif
    close(client_fd);  //Client socket FD not required in bash subprocess
    close(ptymaster_fd);  //PTY master FD not required in bash subprocess
    exec_bash_via_pty(ptyslave_name);

    //Should not get here since bash process should terminate, so if get
    //here indicates failure to be able to run bash for client:
    //(Terminating child will close PTY slave leading to PTY master HUP.)
    exit(EXIT_FAILURE);
  }

  //PARENT process:

  //Add client: setup FD mappings and add FDs to epoll:
  if (!add_client(client_fd,ptymaster_fd))
    pthread_exit(NULL);

  //Ready to handle client commands, so send OK response to client:
  if (write(client_fd,server2ok,strlen(server2ok)) == -1) {
    #ifdef DEBUG
    printf("Error writing OK to client (FD %d)\n",client_fd);
    #endif
    remove_client(client_fd); }

  //Terminate handle-client thread:
  return NULL;
}



// Function to perform initial rembash protocol exchange.
// Return indicates success/failure: 1 for true/success, 0 for false/fail.
// Uses timer to protect against malicious/broken clients blocking indefinitely.
int validate_client_secret(int client_fd)
{
  char buff[513];  //513 for valid string
  ssize_t nread;

  struct sigevent sev;
  timer_t timerid;
  struct itimerspec its;

  //Create timer to ensure client doesn't block indefinitely:
  memset(&sev,0,sizeof(sev));
  sev.sigev_notify = SIGEV_THREAD_ID;  //Linux-specific option so thread-specific!
  //sev.sigev_notify_thread_id = syscall(SYS_gettid);
  sev._sigev_un._tid = syscall(SYS_gettid);
  sev.sigev_signo = SIGALRM;
  if (timer_create(CLOCK_REALTIME,&sev,&timerid) == -1) {
    perror("Server: Error creating timer");
    return 0; }

  //Set timer to 10secs:
  memset(&its,0,sizeof(its));
  its.it_value.tv_sec = 10;
  its.it_value.tv_nsec = 0;

  //Get and check shared secret:
  //First arm timer:
  if (timer_settime(timerid,0,&its,NULL) == -1) {
    perror("Server: Error setting timer");
    return 0; }

  //Get shared secret from client, with timer armed,
  //so read() may fail if timer expires:
  nread = read(client_fd,buff,512);

  //Disarm/delete timer:
  timer_delete(timerid);

  //Check if read error:
  if (nread <= 0) {
    #ifdef DEBUG
    //Check if read error was due to timer expiring or not:
    if (nread == -1 && errno == EINTR)
      printf("Timer expired while waiting to read client secret (FD %d)\n",client_fd);
    else
      printf("Error/EOF reading secret from client (FD %d)\n",client_fd);
    #endif
    return 0;
  }

  //Got secret, so validate it:
  buff[nread] = '\0';
  if (strcmp(buff,SECRET) != 0) {
    #ifdef DEBUG
    printf("Client (FD %d) sent invalid secret\n",client_fd);
    #endif
    return 0; }

  //Successful validation:
  return 1;
}



// Handler for timer SIGALRM signal during initial_protocol_exchange().
// Does nothing; provided so SIGALRM from timer interrupts a blocked
// read() from a socket, but does not terminate the (entire server) process.
// (Want handler to return so read() can return error and have timer deleted.)
void timer_handler(int sig)
{
  #ifdef DEBUG
  printf("timer_handler() invoked!\n");
  #endif

  return;
}



// Function to create new PTY master-slave pair.
// Passes master FD and slave name back via parameters.
// Return indicates success/failure: 1 for true/success, 0 for false/failure
int create_pty_pair(int *ptymasterfd_ptr, char **ptyslavename_ptr)
{
  #ifdef DEBUG
  printf("Creating new PTY pair\n");
  #endif

  int ptymaster_fd;
  char * ptyslave_name;

  if ((ptymaster_fd = posix_openpt(O_RDWR)) == -1) {
    #ifdef DEBUG
    perror("posix_openpt call failed");
    #endif
    return 0; }

  //Need to set PTY master FD so gets closed when bash exec'd:
  fcntl(ptymaster_fd,F_SETFD,FD_CLOEXEC);

  //grantpt(ptymaster_fd);  //Not required on Linux
  unlockpt(ptymaster_fd);

  char *ptyslave_nametmp = ptsname(ptymaster_fd);
  if ((ptyslave_name = (char *)malloc(strlen(ptyslave_nametmp)+1)) == NULL) {
    #ifdef DEBUG
    perror("malloc call failed");
    #endif
    return 0; }
  strcpy(ptyslave_name,ptyslave_nametmp);

  //Normal return:
  *ptymasterfd_ptr = ptymaster_fd;
  *ptyslavename_ptr = ptyslave_name;
  return 1;
}



// Function to setup bash to be run with I/O via PTY and exec bash.
// (Gets run in a separate subprocess so can exec bash.)
// Note:  Should not return due to exec call (and subsequent bash termination),
// so if function returns, it indicates failure to be able to run bash for client!
// Thus caller must be prepared to terminate subprocess if function returns.
void exec_bash_via_pty(char *ptyslave_name)
{
  //Create a new session for the new process:
  if (setsid() == -1) {
    #ifdef DEBUG
    perror("setsid call failed");
    #endif
    return; }

  //Setup PTY for bash subprocess (open PTY slave):
  //(May fail due to PTY master having been closed already due to client hangup.)
  int ptyslave_fd;
  if ((ptyslave_fd = open(ptyslave_name,O_RDWR)) == -1) {
    #ifdef DEBUG
    perror("failed to open PTY slave");
    #endif
    return; }

  //Setup stdin, stdout, and stderr redirection:
  //(May fail due to PTY master having been closed already due to client hangup.)
  if ((dup2(ptyslave_fd,0) == -1) || (dup2(ptyslave_fd,1) == -1) || (dup2(ptyslave_fd,2) == -1)) {
    #ifdef DEBUG
    perror("dup2 call for fd 0, 1, or 2 failed");
    #endif
    return; }

  #ifdef DEBUG
  print_id_info("Starting bash in subprocess: ");
  #endif

  //Start bash running:
  execlp("bash","bash",NULL);

  //Catch exec failure here:
  return;
}



// Function to add validated client to be monitored for I/O transfers:
//  (1) adds the two client FDs to the client FDs mapping table
//  (2) adds the two client FDs to be monitored by epoll for input
int add_client(int sock_fd, int ptymaster_fd)
{
  #ifdef DEBUG
  printf("Adding new client (sockfd: %d, ptymasterfd: %d)\n",sock_fd,ptymaster_fd);
  #endif

  //Add the FDs to the client FDs mapping table:
  fd_client_mapping[sock_fd]=ptymaster_fd;
  fd_client_mapping[ptymaster_fd]=sock_fd;

  //Add the two argument FDs to be epolled for input:
  //Note that if adding fails, this may be due simply to premature
  //closure of client connection causing FDs to already be closed:
  struct epoll_event ev;
  ev.events = EPOLLIN | EPOLLET;
  ev.data.fd = sock_fd;
  if (epoll_ctl(epoll_fd,EPOLL_CTL_ADD,sock_fd,&ev) == -1) {
    #ifdef DEBUG
    perror("Server: failed to add sock_fd for epoll()");
    #endif
    return 0; }
  ev.data.fd = ptymaster_fd;
  if (epoll_ctl(epoll_fd,EPOLL_CTL_ADD,ptymaster_fd,&ev) == -1) {
    #ifdef DEBUG
    perror("Server: failed to add ptymaster_fd for epoll()");
    #endif
    return 0; }

  return 1;
}



// Function to remove/close a client:
// Able to be called with either FD in client pair (socket or PTY master).
// Must work if called repeatedly, i.e., even if already closed client,
// since both client FDs may get EOF/error returns "concurrently."
// NULLs out client FDs mapping table entries to indicate client closed.
void remove_client(int client_fd)
{
  //Get associated FD:
  int other_client_fd = fd_client_mapping[client_fd];

  #ifdef DEBUG
  printf("Removing client (FD: %d, other FD: %d)\n",client_fd,other_client_fd);
  #endif

  //Remove the FDs from epoll unit:
  //(Simply closing them eventually does that, but epoll_wait() may
  //go through several cycles saying ready before they get removed.)
  //(Do not print any messages because FDs may already be closed.)
  epoll_ctl(epoll_fd,EPOLL_CTL_DEL,client_fd,NULL);
  epoll_ctl(epoll_fd,EPOLL_CTL_DEL,other_client_fd,NULL);

  //Try to close client FDs:
  //(close() calls may fail because FDs already were closed.)
  close(client_fd);
  close(other_client_fd);

  return;
}



// Function to monitor PTY and client socket FDs for available input,
// then find matching PTY/socket FD and transfer data between them.
// Runs in separate pthread from main server, runs "forever."
void *epoll_and_transfer_data(void *ignore)
{
  #ifdef DEBUG
  print_id_info("Starting epoll loop in new thread: ");
  #endif

  int ready, sourcefd, targetfd;
  struct epoll_event evlist[MAX_NUMBER_CLIENTS*2];

  //Loop, epolling the FDs:
  while ((ready = epoll_wait(epoll_fd,evlist,MAX_NUMBER_CLIENTS*2,-1)) > 0) {
    //Go through the ready FDs and transfer data:
    for (int i=0; i<ready; i++) {
      //Check for errors on FD before EPOLLIN:
      if (evlist[i].events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) {
        //Error/HUP, so remove client (close its FDS):
        sourcefd = evlist[i].data.fd;
        #ifdef DEBUG
        printf("ERR/HUP/RDHUP on FD: %d\n",sourcefd);
        #endif
        remove_client(sourcefd);
      }
      else if (evlist[i].events & EPOLLIN) {
        //Data is ready to read so transfer:
        sourcefd = evlist[i].data.fd;
        targetfd = fd_client_mapping[sourcefd];
        tpool_add_task(sourcefd);
      }
    }
  }

  //Should never get here unless epoll error (server failure):
  perror("Server: epoll_wait call failed");
  exit(EXIT_FAILURE);  //Server failure!

  return NULL;  //For compiler.
}


void relay_data(int sourcefd) {
  int targetfd = fd_client_mapping[sourcefd];
  char buff[4096];
  ssize_t nread, nwritten, total;

  errno = 0;
  if ((nread = read(sourcefd,buff,4096)) > 0) {
    total = 0;
    do {
      if ((nwritten = write(targetfd,buff+total,nread-total)) == -1) break;
      total += nwritten;
    } while (total < nread);
  }
}

// Function to do actual transfer of data between two FDs.
// read's-write's single block of data.
void relay_data_between_fds(int sourcefd, int targetfd)
{
  #ifdef DEBUG
  printf("Relaying data: %d->%d\n",sourcefd,targetfd);
  #endif

  char buff[4096];
  ssize_t nread, nwritten, total;

  errno = 0;
  if ((nread = read(sourcefd,buff,4096)) > 0) {
    total = 0;
    do {
      if ((nwritten = write(targetfd,buff+total,nread-total)) == -1) break;
      total += nwritten;
    } while (total < nread);
  }

  //See if read got EOF or if read/write error occurred, and if so close FDs:
  //(This causes FDs to be removed from epoll automatically.)
  if (nread == 0 || errno)
    remove_client(sourcefd);

  return;
}



// Function to print out detailed info about a process.
void print_id_info(char *message)
{
  printf("%sPID=%ld, PGID=%ld, SID=%ld, TID=%ld, PPID=%ld, CTERM=%s\n",message,(long)getpid(),(long)getpgrp(),(long)getsid(0),syscall(SYS_gettid),(long)getppid(),ctermid(NULL));
}


// EOF
