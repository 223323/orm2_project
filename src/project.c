// Katedra: Katedra za racunarsku tehniku i racunarske komunikacije
// Predmet: Osnovi racunarskih mreza 2
// Godina studija: III godina
// Semestar: Letnji (VI)
// Skolska godina: 2015/2016
// Datoteka: project.c

#ifdef _MSC_VER
/*
 * we do not want the warnings about the old deprecated and unsecure CRT functions
 * since these examples can be compiled under *nix as well
 */
#define _CRT_SECURE_NO_WARNINGS
#else
#include <stdlib.h>
#include <netinet/in.h>
#include <time.h>
#endif



#include <string.h>
#include <assert.h>
#include <pcap.h>
#include "devices.h"
#include "network_layers.h"


void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
void setup_listen(char* dev, char* filter); // listen.c
int setup_server(char *devlist, int port); // server.c
int setup_client(char *devlist, char *dmaclist, char *diplist, char* dportlist, char *transfer_file); // client.c

void print_help() {
	printf("./project client dev1,...,devn dmac,... dip,... dport,... input_file\n");
	printf("./project server dev1,...,devn\n");
	printf("./project listen dev bpf_filter\n");
	printf("./project list\n");
	printf("./project test\n");
	exit(-1);
}

#include "queue.h"

void test();

int main(int argc, char *argv[])
{
	
	if(argc <= 1) print_help();
	if(!strcmp(argv[1], "server") && argc == 4) {
		char* devlist = argv[2];
		int port = atoi(argv[3]);
		if(port < 1000 || port > 65535) return -1;
		return setup_server(devlist, port);
	} else if(!strcmp(argv[1],"client") && argc == 7) {
		
		char* devlist = argv[2];
		char* dest_mac = argv[3];
		char* dest_ip  = argv[4];
		char* dest_port= argv[5];
		char* transfer_file = argv[6];
		
		return setup_client(devlist, dest_mac, dest_ip, dest_port, transfer_file);
	} else if(!strcmp(argv[1],"list") && argc == 2) {
		list_all_devices();
		return -1;
		
	} else if(!strcmp(argv[1],"listen") && argc == 4) {
		setup_listen(argv[2], argv[3]);
	} else if(!strcmp(argv[1],"test") && argc == 2) {
		test();
	} else {
		print_help();
	}
	
	
	return 0;
}


void test_send_pkt() {
	int t;
	dev_context* dev = load_devices("wlan0", &t);
	send_packet(dev, MAC(00:90:a2:cd:d4:49), IP_ADDR(10.0.0.1), 5000, "heheeh", 5);
}

void test() {
	int i;
	
	// printf("testing queue\n");
	// queue* q = queue_init();
	// printf("enqueue test\n");
	// for(i=0; i < 10; i++) {
		// printf("%d ", i);
		// queue_push(q, i);
	// }
	// printf("\ndequeue test\n");
	// for(i=0; i < 10; i++) {
		// printf("%d ", queue_pop(q));
	// }
	// printf("\n");
	
	test_send_pkt();
}

