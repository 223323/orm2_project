#include "tinycthread.h"

typedef struct queue queue;

typedef int queue_val;

queue* queue_init();
void queue_destroy(queue* q);

void queue_push(queue* q, queue_val el);
queue_val queue_pop(queue* q);
int queue_num_elements(queue* q);
