#include <stdio.h>
#include <stdlib.h>
#include "tpool.h"
#include <unistd.h>
#include <time.h>


void work(int task) {
  printf("working on %d\n", task);
  usleep(13000ULL * rand() / RAND_MAX);
}

int main(int argc, char** argv) {
  tpool_init(work);
  srand(time(NULL));
  int i = 0;
  while (i++ < 40) {
    if (i % 3 == 0) {
     usleep(3100ULL);
    }
    printf("MAIN adding %d\n", i);
    tpool_add_task(i);
  }
  sleep(1);
}
