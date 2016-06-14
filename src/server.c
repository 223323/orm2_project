#include <string.h>
#include <assert.h>
#include <pcap.h>
#include <stdlib.h>
#include "network_layers.h"
#include "devices.h"
#include "packet.h"
#include "tinycthread.h"
#include <unistd.h>

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

#define MAX_FILE_SIZE 5000000000

static void server_thread(struct thread_context* context);

int setup_server(char* devlist, int port) {
	int i=0;

	int n_devices;
	dev_context* devices = load_devices(devlist, &n_devices);

	printf("loaded %d devices\n", n_devices);
	printf("loaded devices are: ");
	list_devices(devices,n_devices);
	printf("\n");

	shared_context shared_ctx;
	shared_ctx.received_init_packet = 0;
	shared_ctx.done = 0;
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

	mtx_destroy(&shared_ctx.mutex);
	free(thread);
	free(thread_contexts);
	free(devices);

	return 0;
}


static void server_thread(struct thread_context* ctx) {
	dev_context* dev = ctx->dev;
	shared_context* shared = ctx->shared;

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
	while(!shared->done) {

		const u_char * data = pcap_next(dev->pcap_handle, &hdr);

		if(!data) {
			// printf("no data (%s)\n", pcap_geterr(dev->pcap_handle));
			usleep(1000);
			if(strstr(pcap_geterr(dev->pcap_handle), "No such device") || 
				strstr(pcap_geterr(dev->pcap_handle), "went down")) {
				/* only if device card is unplugged (like usb wifi)	*/	
				// printf("no such device\n");
				if(!device_reopen(dev, &shared->done)) {				
					return;												
				}														
			}	
			continue;
		}
		udp_packet* udp_pkt = (udp_packet*)data;

		if(!validated_packet(udp_pkt)) {
			continue;
		}
		
		if(!validate_ip(dev, udp_pkt)) {
			continue;
		}

		// check ip and port
		Packet* pkt = (Packet*)udp_pkt->data;

		if(!inited) {
			mtx_lock(&shared->mutex);
			if(shared->received_init_packet == 0 && pkt->type == pkt_type_init) {
				printf("writing to file: %s\n", pkt->init.filename);

				// relative path
				char tmp[50];
				strcpy(tmp, "./");
				strcat(tmp, pkt->init.filename);

				shared->file_size = pkt->init.file_size;
				shared->file = fopen(tmp, "wb");
				shared->received_init_packet = 1;
				shared->max_offset = 0;
				inited = 1;
				mtx_unlock(&shared->mutex);
				reply_ack(dev, udp_pkt);
			} else if(shared->received_init_packet) {
				inited = 1;
				mtx_unlock(&shared->mutex);
			}

			continue;
		}

		if(pkt->type == pkt_type_data) {

			reply_ack(dev, udp_pkt);
			//~ printf("receiving data pkt (%d) %d %d \n", pkt->id, pkt->data.offset, pkt->data.size);
			if(pkt->data.offset + pkt->data.size > shared->file_size) {
				printf("max file size exceeded \n");
				return;
			}

			mtx_lock(&shared->mutex);
			if(pkt->data.offset > shared->max_offset) {
				fseek(shared->file, 0, SEEK_END);
				int to_fill = pkt->data.offset - shared->max_offset;
				#define FILL_BLOCK 500
				int zeros[FILL_BLOCK];

				while(to_fill > 0) {
					int fill_size = min(to_fill, FILL_BLOCK);
					fwrite(zeros, 1, fill_size, shared->file);
					to_fill -= fill_size;
				}
				shared->max_offset = pkt->data.offset;
				fseek(shared->file, 0, SEEK_END);
			} else {
				int fp = ftell(shared->file);
				fseek(shared->file, 0, SEEK_END);
				int fs = ftell(shared->file);
				fseek(shared->file, pkt->data.offset, SEEK_SET);
			}
			fwrite(pkt->data.bytes, 1, pkt->data.size, shared->file);
			if(pkt->data.offset == shared->max_offset)
				shared->max_offset += pkt->data.size;

			mtx_unlock(&shared->mutex);

		} else if(pkt->type == pkt_type_eof) {
			printf("data transfered leaving %s\n", dev->name);
			if(!shared->done) {
				shared->done = 1;
				fclose(shared->file);
				reply_ack(dev, udp_pkt);
			}
			return;
		}
	}
}
