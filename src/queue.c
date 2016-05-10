#include "queue.h"
#include <stdlib.h>

typedef struct queue_el {
	queue_val val;
	struct queue_el* next;
} queue_el;

typedef struct queue {
	int num_elements;
	queue_el *head;
	queue_el *tail;
	mtx_t mutex;
} queue;


queue* queue_init() {
	queue* q = (queue*)malloc(sizeof(queue));
	q->head = q->tail = 0;
	q->num_elements = 0;
	mtx_init(&q->mutex, mtx_plain);
	return q;
}

void queue_destroy(queue* q) {
	if(!q) return;
	queue_el *e, *p;
	e=q->head;
	mtx_destroy(&q->mutex);
	while(e) {
		p = e;
		e=e->next;
		free(p);
	}
	free(q);
}

int queue_num_elements(queue* q) {
	return q->num_elements;
}

void enqueue(queue* q, queue_val val) {
	queue_el* el = (queue_el*)malloc(sizeof(queue_el));
	el->val = val;
	el->next = 0;
	
	mtx_lock(&q->mutex);
	if(q->tail) {
		q->tail->next = el;
	} else {
		q->head = el;
	}
	q->tail = el;
	q->num_elements++;
	mtx_unlock(&q->mutex);
}

queue_val dequeue(queue* q) {
	mtx_lock(&q->mutex);
	queue_el* e = q->head;
	q->head = e->next;
	mtx_unlock(&q->mutex);
	queue_val val = e->val;
	free(e);
	return val;
}
