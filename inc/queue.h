#include "tinycthread.h"

typedef struct queue queue;

typedef int queue_val;

queue* queue_init();
void enqueue(queue* q, int el);
int dequeue(queue* q);
