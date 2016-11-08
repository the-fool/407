#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include "tpool.h"

typedef struct bin_sem {
  pthread_mutex_t mutex;
  pthread_cond_t condition;
  int count;
} bin_sem;

typedef struct task_queue {
  pthread_mutex_t lock;
  bin_sem* has_task;
  size_t len;
  int head;
  int tail;
  int* buffer;
} task_queue;

typedef struct tpool_ {
  pthread_t* threads;
  int num_threads;
  task_queue queue;
} tpool_;

static int task_queue_init();
static int push_task(task_queue* q, int task);
static int pop_task(task_queue* q);
static int is_queue_full(task_queue* q);

static void bin_sem_init(bin_sem* bin_sem);
static void bin_sem_post(bin_sem* sem);

// Global scope & lifetime, per the lab specification
static tpool_ tpool;
static task_queue queue;

int tpool_init(void (*do_task)(int)) {

  tpool.num_threads = (int)sysconf(_SC_NPROCESSORS_ONLN);
  tpool.threads = (pthread_t *) malloc(tpool.num_threads * sizeof(pthread_t*));

  if (tpool.threads == NULL) {
    perror("tpool_init(): Failed to allocate memory for pthread_t*");
    return -1;
  }

  if (task_queue_init() != 0) {
    fprintf(stderr, "task_queue_init");
    return -1;
  }

  return 0;
}

static int task_queue_init() {
  size_t init_len = 4;
  tpool.queue = queue;
  queue.buffer = (int *) malloc(init_len * sizeof(int));
  if (queue.buffer == NULL) {
    perror("task_queue_init(): Failed to allocate memory for queue buffer");
    return -1;
  }
  queue.has_task = (bin_sem*) malloc(sizeof(bin_sem));
  if (queue.has_task == NULL) {
    perror("task_queue_init(): Failed to allocate memory for bin_sem");
    return -1;
  }
  queue.len = init_len;
  queue.head = 0;
  queue.tail = 0;

  pthread_mutex_init(&queue.lock, NULL);
  bin_sem_init(queue.has_task);
  return 0;
}

static int push_task(task_queue* q, int task) {
  if (is_queue_full(q))
    ;
  q->buffer[q->tail] = task;
  q->tail = (q->tail + 1) % q->len;

  return 0; // success
}

static int enlarge_queue(task_queue* q) {
  size_t new_len = q->len * 2;
  q->buffer = (int *) realloc(q->buffer, new_len);
  if (q->buffer == NULL) {
    perror("enlarge_queue(): Failed to realloc for new buffer");
    return -1;
  }
}

static int pop_task(task_queue* q) {
  assert(q->head - q->tail);

  int ret = q->buffer[q->head];
  q->head = (q->head == (int)q->len - 1) ? 0 : q->head + 1;

  return ret;
}

static int is_queue_full(task_queue* q) {
  return ((q->tail + 1) % (int)q->len) == q->head;
}

static void bin_sem_init(bin_sem* sem) {
  pthread_mutex_init(&(sem->mutex), NULL);
  pthread_cond_init(&(sem->condition), NULL);
  sem->count = 0;
}

static void bin_sem_post(bin_sem* sem) {

}
