#include <stdio.h>
#include <stdlib.h>
#include "tpool.h"
#include <unistd.h>
#include <time.h>

int workit = 1;
void work(int task) {
  printf("working on %d :: %d\n", task, workit);
  workit++;
  usleep(13000ULL * (int)sysconf(_SC_NPROCESSORS_ONLN) / 4 * rand() / RAND_MAX);
}

int main(int argc, char** argv) {
  if (tpool_init(work)) {
    fprintf(stderr, "Failed creating pool -- aborting\n");
    exit(EXIT_FAILURE);
  }
  srand(time(NULL));
  int i = 0;
  while (i++ < 40) {
    if (i % 3 == 0) {
     usleep(3100ULL);
    }
    printf("MAIN adding %d\n", i);
    if (tpool_add_task(i)) {
      fprintf(stderr, "Failed adding task to pool\n");
    }
  }
  sleep(1);
  return EXIT_SUCCESS;
}
