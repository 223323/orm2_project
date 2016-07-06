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



#define MAX_FILE_SIZE 5000000000

// ------ packet buffering

#define BUFFER_SIZE 1000 // number of packets in buffer

struct packet_buff {
	int offset;
	int max_offset;
	short *written_bytes;
	char *buff;
	int packet_size;
	int buffer_size;
	FILE* file;
};

struct packet_buff init_packet_buff(int buffer_size, int packet_size, FILE* f) {
	struct packet_buff buf;
	buf.offset = 0;
	buf.max_offset = buffer_size * packet_size;
	buf.written_bytes = (short*)malloc(buffer_size*sizeof(short));
	buf.buffer_size = buffer_size;
	memset(buf.written_bytes, 0, buffer_size);
	buf.buff = (char*)malloc(packet_size*buffer_size);
	buf.packet_size = packet_size;
	buf.file = f;
	return buf;
}

void write_packets(struct packet_buff* buf) {
	int i,a=-1,b,last=a,written_bytes;
	fseek(buf->file, buf->offset, SEEK_SET);
	for(i=0; i < BUFFER_SIZE; i++) {
		if(a == -1 && buf->written_bytes[i] > 0) {
			a = i;
			written_bytes = buf->written_bytes[i];
		} else if(a != -1 && buf->written_bytes[i] != written_bytes) {
			b = i - 1;
			
			fseek(buf->file, (a-last)*buf->packet_size, SEEK_CUR); // maybe SEEK_CUR is faster than SEEK_SET?
			fwrite(buf->buff + (buf->packet_size*a), 1, buf->packet_size*(b-a), buf->file);
			memset(buf->written_bytes + a, 0, b-a); // clean the written_bytes marks
			
			last = a;
			a = -1;
		}
	}
}
int insert_packet(struct packet_buff* buf, int offset, char* packet, int packet_size) {
	if(buf->packet_size != packet_size) return 0;
	if(offset >= buf->offset && offset < buf->max_offset) {
		int pkt_num = (offset-buf->offset) / packet_size;
		if(buf->written_bytes[pkt_num] > 0) return 0;
		memcpy(buf->buff + (offset-buf->offset), packet, packet_size);
		buf->written_bytes[pkt_num] = packet_size;
	} else {
		if(offset > buf->max_offset) {
			write_packets(buf);
			// prepare new buffer
			buf->offset = offset;
			buf->max_offset = buf->offset + buf->buffer_size * buf->packet_size;
		}
	}
	return 1;
}
// --------

typedef struct shared_context {
	int received_init_packet;
	FILE *file;
	size_t file_size;
	mtx_t mutex;
	size_t max_offset;
	struct packet_buff packet_buffer;
	int done;
} shared_context;

typedef struct thread_context {
	dev_context* dev;
	shared_context *shared;
} thread_context;

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
	int packets_in_row = 1;
	int packets_received = 0;
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
				shared->packet_buffer = init_packet_buff(BUFFER_SIZE, pkt->init.packet_size, shared->file);
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
			if(++packets_received == packets_in_row) {
				reply_ack(dev, udp_pkt);
				packets_received = 0;
			}

			if(pkt->data.offset + pkt->data.size > shared->file_size) {
				printf("max file size exceeded \n");
				return;
			}

			mtx_lock(&shared->mutex);
			fseek(shared->file, pkt->data.offset, SEEK_SET);
			// insert packet
			insert_packet(&shared->packet_buffer, pkt->data.offset, pkt->data.bytes, pkt->data.size);
			// fwrite(pkt->data.bytes, 1, pkt->data.size, shared->file);
			// if(pkt->data.offset == shared->max_offset)
				// shared->max_offset += pkt->data.size;

			mtx_unlock(&shared->mutex);

		} else if(pkt->type == pkt_type_eof) {
			printf("data transfered, leaving %s\n", dev->name);
			if(!shared->done) {
				shared->done = 1;
				fclose(shared->file);
				reply_ack(dev, udp_pkt);
			}
			return;
		} else if(pkt->type == pkt_type_control) {
			packets_in_row = pkt->packets_in_row;
			packets_received = 0;
			reply_ack(dev, udp_pkt);
		}
	}
}
