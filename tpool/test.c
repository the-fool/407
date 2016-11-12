#include <stdio.h>
#include <stdlib.h>
#include "tpool.h"
#include <unistd.h>
#include <time.h>


void work(int task) {
  usleep(500000ULL * rand() / RAND_MAX);
  printf("working on %d\n", task);
  usleep(1000000ULL * rand() / RAND_MAX);
}

int main() {
  tpool_init(work);
  //sleep();
  int i = 0;
  while (i++ < 40) {
    //usleep(100000ULL * rand() / RAND_MAX);
    if (i % 3 == 0)
      usleep(700000ULL * rand() / RAND_MAX);
    printf("MAIN adding %d\n", i);
    tpool_add_task(i);
  }

  fgetc(stdin);
}
