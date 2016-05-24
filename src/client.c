#include "tinycthread.h"
#include "devices.h"
#include "packet.h"
#include "queue.h"
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <libgen.h>


static int min(int a, int b) { return a < b ? a : b; }

typedef struct shared_context {
	int sent_init_packet;
	FILE *file;
	char filename[50];
	int file_size;
	char *chunk;
	int chunk_offset;
	int num_blocks;
	mtx_t mutex;
	queue* q;
	int active_devices;
	int done;
} shared_context;

typedef struct thread_context {
	dev_context* dev;
	shared_context *shared;

	// device specific
	int use_udp;
	mac_address mac;
	ip_address ip;
	int port;
} thread_context;

void client_thread(thread_context* ctx);

#define CHUNK_SIZE 1000000
#define BLOCK_SIZE 800
int setup_client(char *devlist, char *dmaclist, char *diplist, char* dportlist, char *transfer_file) {

	int i=0;

	int n_devices;
	dev_context* devices = load_devices(devlist, &n_devices);

	printf("loaded %d devices\n", n_devices);
	printf("loaded devices are: ");
	list_devices(devices, n_devices);
	printf("\n");

	shared_context shared_ctx;
	FILE* f = fopen(transfer_file, "r");
	if(!f) {
		printf("file %s not found\n", transfer_file);
		return -1;
	}
	fseek(f, 0, SEEK_END);
	strcpy(shared_ctx.filename, transfer_file);
	shared_ctx.file_size = ftell(f);
	fseek(f, 0, SEEK_SET);
	shared_ctx.file = f;
	shared_ctx.sent_init_packet = 0;
	shared_ctx.q = queue_init();
	shared_ctx.chunk = malloc(CHUNK_SIZE);
	shared_ctx.chunk_offset = -1;
	
	int blocks = shared_ctx.file_size/BLOCK_SIZE + 1;
	shared_ctx.num_blocks = blocks;
	printf("preparing to send %d blocks of size %d\n", blocks, BLOCK_SIZE);
	for(i=0; i < blocks; i++) {
		queue_push(shared_ctx.q, i);
	}

	mtx_init(&shared_ctx.mutex, mtx_plain);

	char macbuff[50];
	strcpy(macbuff, dmaclist);

	char* t_mac_state;
	char* t_mac = strtok_r(macbuff, ",", &t_mac_state);

	int is_udp_version;

	if(diplist && dportlist)
		is_udp_version = 1;
	else
		is_udp_version = 0;

	char ipbuff[50];
	char portbuff[50];

	char* t_ip;
	char* t_port;
	char* t_ip_state;
	char* t_port_state;

	if(is_udp_version) {
		strcpy(ipbuff, diplist);
		strcpy(portbuff, dportlist);
		t_ip = strtok_r(ipbuff, ",", &t_ip_state);
		t_port = strtok_r(portbuff, ",", &t_port_state);
	}
	shared_ctx.active_devices=0;
	thread_context* thread_contexts = (thread_context*)malloc(sizeof(thread_context)*n_devices);
	thrd_t *thread = (thrd_t*)malloc(sizeof(thrd_t)*n_devices);
	for(i=0; i < n_devices; i++) {
		thread_context* ctx = thread_contexts+i;
		ctx->dev = devices+i;
		ctx->shared = &shared_ctx;

		ctx->use_udp = is_udp_version;

		if(t_mac == 0) {
			printf("Error: not given enough mac addresses\n");
			exit(-1);
		}
		ctx->mac = str2mac(t_mac);

		dump_mac(ctx->mac);

		t_mac = strtok_r(NULL, ",", &t_mac_state);

		if(is_udp_version) {
			if(t_ip == 0) {
				printf("Error: not given enough ip addresses\n");
				exit(-1);
			}
			if(t_port == 0) {
				printf("Error: not given enough ports\n");
				exit(-1);
			}

			ctx->ip = str2ip(t_ip);
			ctx->port = atoi(t_port);

			t_ip = strtok_r(NULL, ",", &t_ip_state);
			t_port = strtok_r(NULL, ",", &t_port_state);
		}

	}

	for(i=0; i < n_devices; i++) {
		thread_context* ctx = thread_contexts+i;
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

thrd_t count_thread;

void countdown_thread(int *active_devices) {
	int counter=10;
	while(*active_devices == 0) {
		printf("%d until termination\n", counter);
		usleep(1000000); // 1 sec
		if(--counter <= 0) {
			printf("no connection, program terminated\n");
			exit(-1);
		}
	}
}

#define SEND_PACKET_AND_WAIT_ACK(pkt) 											\
	if(reliably_send_packet_udp(dev, pkt, ctx->mac, ctx->ip, ctx->port) == 0) { \
		if(connected) {                                                         \
			mtx_lock(&shared->mutex);											\
			shared->active_devices--;                                           \
			ctx->dev = 0;														\
			connected = 0;														\
			printf("device %s disconnected\n", dev->name); 						\
			mtx_unlock(&shared->mutex);                                         \
			if(shared->active_devices == 0) {                                   \
			thrd_create(&count_thread,                                          \
				(thrd_start_t)countdown_thread, &shared->active_devices);       \
			}                                                                   \
		}                                                                       \
		/* return block to queue for other devices to finish */ 				\
		if(processing_block != -1) { 											\
			mtx_lock(&shared->mutex); 											\
			queue_push(shared->q, processing_block);							\
			mtx_unlock(&shared->mutex);											\
		}																		\
		if(strstr(pcap_geterr(dev->pcap_handle), "No such device")) {			\
			/* only if device card is unplugged (like usb wifi)	*/				\
			if(!device_reopen(dev, &shared->done)) {							\
				return;															\
			}																	\
		}																		\
		/* it just reconnected and didn't send any packets */					\
		continue;																\
	}																			\
	if(!connected) {                                                            \
		printf("device %s reconnected\n", dev->name);                           \
		connected = 1;                                                          \
		shared->active_devices++;												\
	}																			\


void client_thread(thread_context* ctx) {
	dev_context* dev = ctx->dev;
	shared_context* shared = ctx->shared;

	int connected = 0;

	printf("hello from: %s\n", dev->name);

	if(!dev->pcap_handle) {
		if(!device_reopen(dev, &shared->done))
			return;
	}

	mtx_lock(&shared->mutex);
	shared->active_devices++;
	connected = 1;
	device_set_filter(dev, "ip and udp");
	mtx_unlock(&shared->mutex);

	int num_elements;
	int processing_block = -1;
	int data_length;

	while(1) {

		mtx_lock(&shared->mutex);
		if(shared->sent_init_packet == 0) {
			Packet pkt_init;
			pkt_init.signature = SIGNATURE;
			pkt_init.type = pkt_type_init;
			strcpy(pkt_init.init.filename, basename(shared->filename));
			printf("sending file %s\n", pkt_init.init.filename);
			pkt_init.init.file_size = shared->file_size;
			pkt_init.size = PACKET_HEADER_SIZE + PACKET_INIT_HEADER_SIZE +
				strlen(pkt_init.init.filename) + 1;

			// while waiting, let other thread also try send init packet
			mtx_unlock(&shared->mutex);

			SEND_PACKET_AND_WAIT_ACK(&pkt_init);
			shared->sent_init_packet = 1;
			continue;
		}

		if(queue_num_elements(shared->q) > 0) {
			processing_block = queue_pop(shared->q);
			printf("[%s] sending block %d/%d\n", dev->name, processing_block, shared->num_blocks);
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
			
			data_length = min(BLOCK_SIZE, shared->file_size-processing_block*BLOCK_SIZE);
			// printf("sending %d bytes\n", data_length);
			
			if(shared->chunk_offset < 0 || processing_block*BLOCK_SIZE+BLOCK_SIZE > shared->chunk_offset+CHUNK_SIZE) {
				printf("NEW CHUNK\n");
				shared->chunk_offset = processing_block*BLOCK_SIZE;
				fseek(shared->file, shared->chunk_offset, SEEK_SET);
				fread(shared->chunk, 1, CHUNK_SIZE, shared->file);
				usleep(5000000);
			}
		}
		mtx_unlock(&shared->mutex);

		if(processing_block != -1) {
			Packet pkt_data;
			pkt_data.signature = SIGNATURE;
			pkt_data.type = pkt_type_data;
			pkt_data.data.size = data_length;
			pkt_data.data.offset = processing_block*BLOCK_SIZE;
			assert(processing_block*BLOCK_SIZE+BLOCK_SIZE <= shared->chunk_offset+CHUNK_SIZE);
			assert(processing_block*BLOCK_SIZE >= shared->chunk_offset);
			memcpy(pkt_data.data.bytes, 
				shared->chunk+(processing_block*BLOCK_SIZE-shared->chunk_offset), data_length);
			pkt_data.size = PACKET_HEADER_SIZE + PACKET_DATA_HEADER_SIZE + data_length;
			// printf("data size %d\n", pkt_data.size);
			SEND_PACKET_AND_WAIT_ACK(&pkt_data);
			processing_block = -1;
		}
	}
}
