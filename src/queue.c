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
} queue;


queue* queue_init() {
	queue* q = (queue*)malloc(sizeof(queue));
	q->head = q->tail = 0;
	q->num_elements = 0;
	return q;
}

void queue_destroy(queue* q) {
	if(!q) return;
	queue_el *e, *p;
	e=q->head;
	while(e) {
		p = e;
		e=e->next;
		free(p);
	}
	free(q);
}

int queue_num_elements(queue* q) {
	int num_elements;
	num_elements = q->num_elements;
	return num_elements;
}

void queue_push(queue* q, queue_val val) {
	queue_el* el = (queue_el*)malloc(sizeof(queue_el));
	el->val = val;
	el->next = 0;

	if(q->tail) {
		q->tail->next = el;
	} else {
		q->head = el;
	}
	q->tail = el;
	q->num_elements++;
}

queue_val queue_pop(queue* q) {
	if(!q->head) return -1;
	queue_el* e = q->head;
	q->head = e->next;
	if(!q->head) q->tail = 0;
	queue_val val = e->val;
	free(e);
	q->num_elements--;
	return val;
}
