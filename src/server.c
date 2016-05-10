#include <string.h>
#include <assert.h>
#include <pcap.h>
#include <stdlib.h>
#include "network_layers.h"
#include "devices.h"
#include "queue.h"
#include "packet.h"
#include <unistd.h>
#include "tinycthread.h"

typedef struct thread_context {
	dev_context* dev;
	FILE** f;
	int *received_init_packet;
	mtx_t *mutex;
} thread_context;

static void server_thread(struct thread_context* context);

int setup_server(char* devlist) {
	int i=0;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	char packet_filter[] = "ip and udp";
	struct bpf_program fcode;
	
	int n_devices;
	int received_init_packet;
	dev_context* devices = load_devices(devlist, &n_devices);
	
	printf("loaded %d devices\n", n_devices);
	printf("loaded devices are: ");
	list_devices(devices,n_devices);
	printf("\n");
	
	mtx_t shared_mutex;
	mtx_init(&shared_mutex, mtx_plain);
	thread_context* thread_contexts = (thread_context*)malloc(sizeof(thread_context)*n_devices);
	thrd_t *thread = (thrd_t*)malloc(sizeof(thrd_t)*n_devices);
	for(i=0; i < n_devices; i++) {
		thread_context* ctx = thread_contexts+i;
		ctx->dev = devices+i;
		ctx->received_init_packet = &received_init_packet;
		ctx->mutex = &shared_mutex;
		thrd_create(&thread[i], (thrd_start_t)server_thread, ctx);
	}
	
	for(i=0; i < n_devices; i++) {
		thrd_join(thread[i],0);
	}
	
	free(thread);
	free(thread_contexts);
	free_devices(devices, n_devices);
}


void reconnect(dev_context* dev) {
	while(!try_open_device(dev)) {
		sleep(1);
	}
}

static void server_thread(struct thread_context* context) {
	dev_context* dev = context->dev;
	
	printf("hello from: %s\n", dev->name);
	
	int current_processing = 0;
	int i;
	
	if(!dev->pcap_handle) {
		reconnect(dev);
		printf("connected to %s\n", dev->name);
	}
	
	mtx_lock(context->mutex);
	device_set_filter(dev, "ip and udp");
	mtx_unlock(context->mutex);
	
	int num_parts;
	int filesize;
	char filename[100];
	
	while(1) {
		struct pcap_pkthdr hdr;
		const u_char * data = pcap_next(dev->pcap_handle, &hdr);
		
		if(!data) continue;
		
		udp_packet* pkt = (udp_packet*)data;
		
		if(!validated_packet(pkt)) continue;
		
		int data_len = packet_get_data_length(pkt);
		
		for(i=0; i < hdr.len; i++) {
			printf("%0.2X ", data[i]); 
		}
		
		for(i=0; i < data_len; i++) {
			printf("%c", pkt->data[i]);
		}
		
		printf("\n---------\n");
	}
	
}
