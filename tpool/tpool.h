#ifndef _RUBLE_POOL_
#define _RUBLE_POOL_

typedef struct tpool_* coolpool;

int tpool_init(void (*do_task)(int));

int tpool_add_task(int newtask);

#endif
