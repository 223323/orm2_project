#include <string.h>
#include <assert.h>
#include <pcap.h>
#include <stdlib.h>
#include "network_layers.h"
#include "devices.h"
#include "queue.h"
#include "packet.h"


static void server_thread(dev_context* dev, queue* q, FILE* f);

int setup_server(char* devlist) {
	int i=0;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	char packet_filter[] = "ip and udp";
	struct bpf_program fcode;
	
	int n_devices;
	dev_context* devices = load_devices(devlist, &n_devices);
	
	printf("loaded %d devices\n", n_devices);
	printf("loaded devices are: ");
	list_devices(devices,n_devices);
	printf("\n");
	/* start the capture */
	// pcap_loop(adhandle, 0, packet_handler, NULL);
	
	thrd_t *thread = (thrd_t*)malloc(sizeof(thrd_t)*n_devices);
	for(i=0; i < n_devices; i++) {
		thrd_create(&thread[i], (thrd_start_t)server_thread, &devices[i]);
	}
	
	for(i=0; i < n_devices; i++) {
		thrd_join(thread[i],0);
	}
	
	// send_packet(&devices[0], MAC(00:90:a2:cd:d4:49), IP_ADDR(10.0.0.1), 5000, "hehhehe");
	
}


static void server_thread(dev_context* dev, queue* q, FILE* f) {
	printf("hello from: %s\n", dev->d->name);
	
	int current_processing = 0;
	int i;
	
	// implement simple receive
	
	device_set_filter(dev, "ip and udp");
	
	int num_parts;
	int filesize;
	char filename[100];
	
	
	while(1) {
		struct pcap_pkthdr hdr;
		const u_char * data = pcap_next(dev->pcap_handle, &hdr);
		
		if(!data) continue;
		
		for(i=0; i < hdr.len; i++) {
			printf("%0.2X ", data[i]); 
		}
		udp_packet* pkt = (udp_packet*)data;
		
		if(pkt->ip.ver_ihl != 0x45) {
			printf("received data with ip.ver_ihl = % not supported, skipping !\n", pkt->ip.ver_ihl);
			continue;
		}
		
		printf("\ndata on port %d is ... \n", htons(pkt->udp.dport));
		int data_len = htons(pkt->udp.len) - sizeof(udp_header);
		
		Packet *mypkt = (Packet*)pkt->data;
		
		printf("test filesize %d\n", mypkt->intro.file_size);
		
		if(data_len < UDP_PACKET_DATA_SIZE) {	
			for(i=0; i < data_len; i++) {
				printf("%c", pkt->data[i]);
			}
		} else {
			printf("couldn't display data with size %d\n", data_len);
		}
		printf("\n---------\n");
	}
	
}
