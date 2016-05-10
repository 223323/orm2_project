#include "devices.h"
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include "network_layers.h"

pcap_if_t *alldevs;

pcap_if_t* get_alldevs() { return alldevs; }

dev_context* load_devices(char* devlist, int *n_devices) {

	
	int i;
	char* t;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	
	if(pcap_findalldevs(&alldevs, errbuf) == -1) {
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
	
	int num_devs = 0;
	char* devs = malloc(strlen(devlist)+1);
	strcpy(devs,devlist);
	
	// count devices in array
	for(t=strtok(devs, ","); t; t=strtok(0, ","), num_devs++);
	
	dev_context* dc = (dev_context*)malloc(sizeof(dev_context)*num_devs);
	
	int loaded_devices = 0;
	// iterate devices in array
	for(i=0,t=strtok(devs, ","); i < num_devs; t=strtok(0, ","), i++) {
		
		pcap_if_t *d;
		pcap_t *adhandle;
		u_int netmask;
		
		for(d=alldevs; d; d=d->next) {
			if(!strcmp(d->name, t)) {
				break;
			}
		}
		
		if(!d) {
			printf("ERROR: interface %s not found, skipping !\n", d->name);
			continue;
		}
		
		if ((adhandle = pcap_open_live(d->name, 65536,1,1000,errbuf)) == NULL) {
			fprintf(stderr,"\nUnable to open the adapter. %s is not supported by libpcap, skipping !\n", d->name);
			continue;
		}
		
		if(pcap_datalink(adhandle) != DLT_EN10MB) {
			fprintf(stderr,"\n%s is not using ethernet stack, skipping !\n", d->name);
			continue;
		}
		
		
		#ifdef _WIN32
			if(d->addresses != NULL)
				/* Retrieve the mask of the first address of the interface */
				netmask=((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
			else
				/* If the interface is without addresses we suppose to be in a C class network */
				netmask=0xffffff;
		#else
			if (!d->addresses->netmask)
				netmask = 0;
			else
				netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.s_addr;
		#endif
		
		/*
		//compile the filter
		if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) <0 )
		{
			fprintf(stderr,"\nUnable to compile the packet filter. Check the syntax.\n");
			pcap_close(adhandle);
			continue;
		}
		
		//set the filter
		if (pcap_setfilter(adhandle, &fcode)<0)
		{
			fprintf(stderr,"\nError setting the filter.\n");
			pcap_close(adhandle);
			continue;
		}
		*/
		
		dev_context *c = &dc[loaded_devices++];
		
		c->processing_block_num = -1;
		c->pcap_handle = adhandle;
		c->d = d;
		c->last_id = -1;
	}
	
	free(devs);
	*n_devices = loaded_devices;
	
	return dc;
}
