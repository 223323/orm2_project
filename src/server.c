#include <string.h>
#include <assert.h>
#include <pcap.h>
#include <stdlib.h>
#include "network_layers.h"
#include "devices.h"
#include "packet.h"
#include "tinycthread.h"

static int min(int a, int b) { return a < b ? a : b; }

typedef struct shared_context {
	int received_init_packet;
	FILE *file;
	int file_size;
	mtx_t mutex;
	int max_offset;
	int done;
} shared_context;

typedef struct thread_context {
	dev_context* dev;
	shared_context *shared;
} thread_context;

#define MAX_FILE_SIZE 50000000

static void server_thread(struct thread_context* context);

int setup_server(char* devlist) {
	int i=0;

	int n_devices;
	dev_context* devices = load_devices(devlist, &n_devices);

	printf("loaded %d devices\n", n_devices);
	printf("loaded devices are: ");
	list_devices(devices,n_devices);
	printf("\n");

	shared_context shared_ctx;
	shared_ctx.received_init_packet = 0;
	mtx_init(&shared_ctx.mutex, mtx_plain);

	thread_context* thread_contexts = (thread_context*)malloc(sizeof(thread_context)*n_devices);
	thrd_t *thread = (thrd_t*)malloc(sizeof(thrd_t)*n_devices);
	for(i=0; i < n_devices; i++) {
		thread_context* ctx = thread_contexts+i;
		ctx->dev = devices+i;
		ctx->shared = &shared_ctx;
		thrd_create(&thread[i], (thrd_start_t)server_thread, ctx);
	}

	for(i=0; i < n_devices; i++) {
		thrd_join(thread[i],0);
	}

	free(thread);
	free(thread_contexts);
	free_devices(devices, n_devices);
}

void print_percentage() {
	// TODO
	printf("%d", 25);
}

static void server_thread(struct thread_context* ctx) {
	dev_context* dev = ctx->dev;
	shared_context* shared = ctx->shared;

	printf("hello from: %s\n", dev->name);

	int i;

	if(!dev->pcap_handle) {
		if(!device_reopen(dev, &shared->done))
			return;
		printf("connected to %s\n", dev->name);
	}

	mtx_lock(&shared->mutex);
	device_set_filter(dev, "ip and udp");
	mtx_unlock(&shared->mutex);
	
	

	int num_parts;
	int filesize;

	int inited = 0;
	int timeout_num = 0;
	struct pcap_pkthdr hdr;
	int period = 0;
	time_t last_pkt_time = time(NULL);
	#define DEVICE_TIMEOUT 3000
	while(!shared->done) {

		if(time(NULL) - last_pkt_time > DEVICE_TIMEOUT) {
			printf("timeout\n");
			exit(-1);
		}

		const u_char * data = pcap_next(dev->pcap_handle, &hdr);

		if(!data) continue;

		udp_packet* udp_pkt = (udp_packet*)data;

		if(!validated_packet(udp_pkt)) {
			//printf("\npkt not good\n");
			continue;
		}
		
		// check ip and port

		Packet* pkt = (Packet*)udp_pkt->data;

		last_pkt_time = time(0);

		if(!inited) {
			mtx_lock(&shared->mutex);
			printf("reading init pkt %d %d\n", shared->received_init_packet, pkt->type);
			if(shared->received_init_packet == 0 && pkt->type == pkt_type_init) {
				printf("writing to file: %s\n", pkt->init.filename);

				// relative path
				char tmp[50];
				strcpy(tmp, "./");
				strcat(tmp, pkt->init.filename);

				shared->file_size = pkt->init.file_size;
				shared->file = fopen(tmp, "w");
				shared->received_init_packet = 1;
				shared->max_offset = 0;
				inited = 1;
			} else if(shared->received_init_packet) {
				inited = 1;
			}

			mtx_unlock(&shared->mutex);
			
			reply_ack(dev, udp_pkt);
			continue;
		}

		// TODO: server doesn't receive ack, but if didn't receive any data packets
		// 		 assume disconnected
		if(pkt->type == pkt_type_data) {
			
			reply_ack(dev, udp_pkt);
			printf("receiving data pkt %d %d \n", pkt->data.offset, pkt->data.size);
			if(pkt->data.offset + pkt->data.size > shared->file_size) {
				printf("max file size exceeded \n");
				return;
			}

			mtx_lock(&shared->mutex);
			if(pkt->data.offset > shared->max_offset) {
				printf("need to extend offset from %d to %d\n", shared->max_offset, pkt->data.offset);
				fseek(shared->file, 0, SEEK_END);
				printf("now at %d\n", (int)ftell(shared->file));
				int to_fill = pkt->data.offset - shared->max_offset;
				#define FILL_BLOCK 500
				int zeros[FILL_BLOCK];

				while(to_fill > 0) {
					int fill_size = min(to_fill, FILL_BLOCK);
					fwrite(zeros, 1, fill_size, shared->file);
					to_fill -= fill_size;
				}
				shared->max_offset = pkt->data.offset;
			} else {
				printf("seek to %d\n", (int)pkt->data.offset);
				fseek(shared->file, pkt->data.offset, SEEK_SET);
			}
			//printf("writing ==%s==\n", pkt->data.bytes);
			fwrite(pkt->data.bytes, 1, pkt->data.size, shared->file);
			if(pkt->data.offset == shared->max_offset)
				shared->max_offset += pkt->data.size;

			// if(++period > 10) {
				// period = 0;
				// print_percentage();
			// }
			mtx_unlock(&shared->mutex);

			
		} else if(pkt->type == pkt_type_eof) {
			shared->done = 1;
			printf("data transfered\n");
			reply_ack(dev, udp_pkt);
			return;
		}

		int data_len = packet_get_data_length(udp_pkt);

		// for(i=0; i < hdr.len; i++) {
			// printf("%0.2X ", data[i]);
		// }
		
		// printf("\n\n");

		// for(i=0; i < data_len; i++) {
			// printf("%c", udp_pkt->data[i]);
		// }

		printf("\n---------\n");
	}

}
