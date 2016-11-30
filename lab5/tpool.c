#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include "tpool.h"

#define DEBUG 0

typedef struct sem {
  pthread_mutex_t mutex;
  pthread_cond_t condition;
  int flag;
} sem;

typedef struct thread {
  char id; // human readable
  pthread_t pthread_id;
} thread;

typedef struct task_queue {
  pthread_mutex_t lock;  // lock for read-write actions on queue
  sem* has_task; // condition for presence of tasks on queue
  size_t len;
  int head;
  int tail;
  int* buffer;
} task_queue;

typedef struct tpool_ {
  thread** threads;
  int num_threads;
  void (*subroutine)(int);
  task_queue* queue;
} tpool_t;

static void* thread_loop(void* thread);
static int thread_init(thread** threadpp, int ord);

static int task_queue_init();
static int push_task(task_queue* q, int task);
static int pop_task(task_queue* q);
static int is_queue_full(task_queue* q);
static int enlarge_queue(task_queue* q);
static void print_queue(task_queue* q);
static void sem_init(sem* sem);
static void sem_post(sem* sem);
static void sem_wait(sem* sem);

// Global scope & lifetime, per the lab specification
static tpool_t tpool;
// If the pool is global, might as well do the same with the queue!
static task_queue queue;

int tpool_init(void (*do_task)(int)) {

  tpool.num_threads = (int)sysconf(_SC_NPROCESSORS_ONLN);
  //tpool.num_threads = 4;
  tpool.subroutine = do_task;

  if (task_queue_init() != 0) {
    fprintf(stderr, "task_queue_init");
    return -1;
  }

  tpool.threads = (thread**) malloc(tpool.num_threads * sizeof(thread*));
  if (tpool.threads == NULL) {
    perror("tpool_init(): Failed to allocate memory for thread**");
    return -1;
  }

  int i = 0;
  do {
    if (thread_init(&(tpool.threads[i]), i)) {
      fprintf(stderr, "Error creating thread -- aborting\n");
      return -1;
    }
    #if DEBUG
    printf("created thread %c\n", tpool.threads[i]->id);
    #endif
  } while (++i < tpool.num_threads);


  return 0; // success
}

int tpool_add_task(int task) {
  int ret;
  pthread_mutex_lock(&tpool.queue->lock);
  ret = push_task(tpool.queue, task);
  pthread_mutex_unlock(&tpool.queue->lock);
  return ret;
}

static int thread_init(thread** threadpp, int ord) {
  *threadpp = (thread*) malloc(sizeof(thread));
  if (threadpp == NULL) {
    perror("thread_init(): Failed to allocate memory for thread");
    return -1;
  }
  (*threadpp)->id = 'A' + ord;
  pthread_create(&((*threadpp)->pthread_id), NULL, thread_loop, (*threadpp));
  pthread_detach((*threadpp)->pthread_id);
  return 0;
}


static void* thread_loop(void* _thread) {
  int task;

  thread* td;
  td = (thread*) _thread;
  for(;;) {
    // Wait for the queue to be non-empty
    sem_wait(tpool.queue->has_task);
    // Lock queue to pop a single task
    pthread_mutex_lock(&tpool.queue->lock);
    task = pop_task(tpool.queue);
    #if DEBUG
    printf("Worker %c: got %d\n", td->id, task);
    print_queue(tpool.queue);
    #endif
    pthread_mutex_unlock(&tpool.queue->lock);

    tpool.subroutine(task);
    #if DEBUG
    printf("Worker %c: finished %d\n", td->id, task);
    #endif
  }
  return NULL;
}

static int task_queue_init() {
  size_t init_len = 4;
  tpool.queue = &queue;
  queue.buffer = (int *) malloc(init_len * sizeof(int));
  if (queue.buffer == NULL) {
    perror("task_queue_init(): Failed to allocate memory for queue buffer");
    return -1;
  }
  queue.has_task = (sem*) malloc(sizeof(sem));
  if (queue.has_task == NULL) {
    perror("task_queue_init(): Failed to allocate memory for sem");
    return -1;
  }
  queue.len = init_len;
  queue.head = 0;
  queue.tail = 0;

  pthread_mutex_init(&queue.lock, NULL);
  sem_init(queue.has_task);
  return 0;
}

static int push_task(task_queue* q, int task) {
  if (is_queue_full(q) && enlarge_queue(q)) {
    fprintf(stderr, "Enlarge queue failed\n");
    return -1;
  }

  q->buffer[q->tail] = task;
  q->tail = (q->tail + 1) % q->len;
  #if DEBUG
  printf("Q got %d \n", task);
  #endif
  sem_post(q->has_task);

  return 0; // success
}

static int enlarge_queue(task_queue* q) {
  static int i;
  size_t new_len = q->len * 2;
  q->buffer = (int *) realloc(q->buffer, new_len * sizeof(int));
  if (q->buffer == NULL) {
    perror("enlarge_queue(): Failed to realloc for new buffer");
    return -1;
  }

  // if the head is past the tail, then the queue is split
  // the head-to-end section must be shifted up
  if (q->head > q->tail) {
    for (i = q->head; i < (int)q->len; i++) {
      q->buffer[q->len + i] = q->buffer[i];
    }
    q->head += q->len;
  }
  q->len = new_len;

  #if DEBUG
  printf("Enlarged queue :: ");
  print_queue(q);
  #endif

  return 0; // success
}

static int pop_task(task_queue* q) {
  // The queue must have a task!
  assert(q->head - q->tail);

  int ret = q->buffer[q->head];
  q->head = (q->head  + 1) % q->len;
  return ret;
}

static int is_queue_full(task_queue* q) {
  return ((q->tail + 1) % (int)q->len) == q->head;
}


#if DEBUG
  static void print_queue(task_queue* q) {
    int i = 0;
    printf(" [ ");
    while (i < (int)q->len) {
      if (((q->tail > q->head) && (i < q->tail) && (i >= q->head)) ||
          ((q->tail < q->head) && ((i < q->tail) || (i >= q->head))))
        printf(" %d ", q->buffer[i]);
      else
        printf(" - ");
      i++;
    }
    printf(" ] \n\n");
  }
#endif



// --  Convenient semaphore wrappers -- //


static void sem_init(sem* sem) {
  pthread_mutex_init(&(sem->mutex), NULL);
  pthread_cond_init(&(sem->condition), NULL);
  sem->flag = 0;
}

static void sem_post(sem* sem) {
  pthread_mutex_lock(&sem->mutex);
  sem->flag += 1;
  pthread_cond_signal(&sem->condition);
  pthread_mutex_unlock(&sem->mutex);
}

static void sem_wait(sem* sem) {
	pthread_mutex_lock(&sem->mutex);
  assert(sem->flag >= 0);
	while (sem->flag == 0) {
		pthread_cond_wait(&sem->condition, &sem->mutex);
	}
	sem->flag -= 1;
	pthread_mutex_unlock(&sem->mutex);
}
