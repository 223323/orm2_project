#include "tinycthread.h"

typedef struct queue queue;

typedef int queue_val;

queue* queue_init();
void queue_destroy(queue* q);

void queue_push(queue* q, int el);
int queue_pop(queue* q);
int queue_num_elements(queue* q);
