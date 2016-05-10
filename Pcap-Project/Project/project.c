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
#include "network_layers.h"


void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

void setup_listen(char* dev, char* filter); // listen.c
int setup_server(char *devlist); // server.c
int setup_client(char *devlist, char *dmac, char *dip, int dport, char *transfer_file); // client.c

void print_help() {
	printf("./project client dev1,...,devn dmac dip dport input_file\n");
	printf("./project server dev1,...,devn output_file\n");
	printf("./project listen dev bpf_filter\n");
	printf("./project list\n");
	exit(-1);
}

int main(int argc, char *argv[])
{
	
	int i;
	
	if(argc <= 1) print_help();
	if(!strcmp(argv[1], "server") && argc == 3) {
		char* devlist = argv[2];
		return setup_server(devlist);
	} else if(!strcmp(argv[1],"client") && argc == 7) {
		
		char* devlist = argv[2];
		char* dest_mac = argv[3];
		char* dest_ip  = argv[4];
		char* dest_port= argv[5];
		char* transfer_file = argv[6];
		
		int i_dest_port = atoi(argv[5]);
		return setup_client(devlist, dest_mac, dest_ip, i_dest_port, transfer_file);
	} else if(!strcmp(argv[1],"list") && argc == 2) {
		
		pcap_if_t *alldevs;
		pcap_if_t *d;
		for(d=alldevs; d; d=d->next)
		{
			printf("%d. %s", ++i, d->name);
			if (d->description)
				printf(" (%s)\n", d->description);
			else
				printf(" (No description available)\n");
		}
		pcap_freealldevs(alldevs);
		return -1;
		
	} else if(!strcmp(argv[1],"listen") && argc == 4) {
		setup_listen(argv[2], argv[3]);
	} else {
		print_help();
	}
	
	
	return 0;
}






