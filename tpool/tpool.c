#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include "tpool.h"


typedef struct task_queue {
  pthread_mutex_t lock;
  int len;
  int* head;
  int* tail;
} task_queue;

typedef struct tpool_ {
  pthread_t* threads;
  int num_threads;
  task_queue* queue_p;
} tpool_;

static int task_queue_init();


static tpool_ tpool;
static task_queue queue;

int tpool_init(void (*do_task)(int)) {

  tpool.num_threads = (int)sysconf(_SC_NPROCESSORS_ONLN);
  tpool.threads = (pthread_t *) malloc(tpool.num_threads * sizeof(pthread_t*));

  if (tpool.threads == NULL) {
    perror("tpool_init(): Failed to allocate memory for pthread_t*");
    return -1;
  }

  return 0;
}

static int task_queue_init() {

}
