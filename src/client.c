#include "tinycthread.h"
#include "devices.h"
#include "packet.h"
#include "queue.h"
#include <stdlib.h>
#include <string.h>

static int min(int a, int b) { return a < b ? a : b; }

typedef struct shared_context {
	int sent_init_packet;
	FILE *file;
	char filename[50];
	int file_size;
	mtx_t mutex;
	queue* q;
	int done;
} shared_context;

typedef struct thread_context {
	dev_context* dev;
	shared_context *shared;
	
	// device specific
	mac_address mac;
	ip_address ip;
	int port;
} thread_context;

void client_thread(thread_context* ctx);

#define BLOCK_SIZE 500
int setup_client(char *devlist, char *dmac, char *dip, int dport, char *transfer_file) {
	
	int i=0;
	
	int n_devices;
	int received_init_packet;
	dev_context* devices = load_devices(devlist, &n_devices);
	
	printf("loaded %d devices\n", n_devices);
	printf("loaded devices are: ");
	list_devices(devices,n_devices);
	printf("\n");
	
	shared_context shared_ctx;
	FILE* f = fopen(transfer_file, "r");
	fseek(f, 0, SEEK_END);
	strcpy(shared_ctx.filename, transfer_file);
	shared_ctx.file_size = ftell(f);
	fseek(f, 0, SEEK_SET);
	shared_ctx.file = f;
	shared_ctx.sent_init_packet = 0;
	shared_ctx.q = queue_init();
	
	mtx_init(&shared_ctx.mutex, mtx_plain);
	
	thread_context* thread_contexts = (thread_context*)malloc(sizeof(thread_context)*n_devices);
	thrd_t *thread = (thrd_t*)malloc(sizeof(thrd_t)*n_devices);
	for(i=0; i < n_devices; i++) {
		thread_context* ctx = thread_contexts+i;
		ctx->dev = devices+i;
		ctx->shared = &shared_ctx;
		thrd_create(&thread[i], (thrd_start_t)client_thread, ctx);
	}
	
	for(i=0; i < n_devices; i++) {
		thrd_join(thread[i],0);
	}
	
	queue_destroy(shared_ctx.q);
	free(thread);
	free(thread_contexts);
	free_devices(devices, n_devices);
}

#define SEND_PACKET_AND_WAIT_ACK(pkt) \
	if(reliably_send_packet_udp(dev, pkt, ctx->mac, ctx->ip, ctx->port) == 0) { \
		if(!reconnect(dev, &shared->done)) { \
			return; \
		} \
	} 

void client_thread(thread_context* ctx) {
	dev_context* dev = ctx->dev;
	shared_context* shared = ctx->shared;
	int num_elements;
	int processing_block = -1;
	char block[BLOCK_SIZE];
	int data_length;
	while(1) {
		
		mtx_lock(&shared->mutex);
		if(shared->sent_init_packet == 0) {
			Packet pkt_init;
			pkt_init.signature = SIGNATURE;
			pkt_init.type = pkt_type_init;
			strcpy(pkt_init.init.filename, shared->filename);
			pkt_init.init.file_size = shared->file_size;
			pkt_init.size = PACKET_HEADER_SIZE + 4 + strlen(pkt_init.init.filename);
			
			// while waiting, let other thread also try send init packet
			mtx_unlock(&shared->mutex);
			
			SEND_PACKET_AND_WAIT_ACK(&pkt_init);
			continue;
		}
		
		if(queue_num_elements(shared->q) > 0) {
			processing_block = queue_pop(shared->q);
		} else {
			printf("transfer done leaving %s device\n", dev->name);

			Packet pkt_eof;
			pkt_eof.signature = SIGNATURE;
			pkt_eof.type = pkt_type_eof;
			pkt_eof.size = PACKET_HEADER_SIZE;
			
			SEND_PACKET_AND_WAIT_ACK(&pkt_eof);
			return;
		}
		if(processing_block >= 0) {			
			fseek(shared->file, processing_block*BLOCK_SIZE, SEEK_SET);
			data_length = min(BLOCK_SIZE, shared->file_size-processing_block*BLOCK_SIZE);
			fread(block, 1, data_length, shared->file);
		}
		mtx_unlock(&shared->mutex);
		
		Packet pkt_data;
		pkt_data.signature = SIGNATURE;
		pkt_data.type = pkt_type_data;
		pkt_data.data.size = data_length;
		pkt_data.data.offset = processing_block*BLOCK_SIZE;
		pkt_data.size = PACKET_HEADER_SIZE + 8 + pkt_data.data.size;
		SEND_PACKET_AND_WAIT_ACK(&pkt_data);
	}
}
