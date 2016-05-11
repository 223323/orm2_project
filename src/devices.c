#include "devices.h"
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include "network_layers.h"

static pcap_if_t *alldevs = 0;
static int n_devices_in_use = 0;

pcap_if_t* get_alldevs() { return alldevs; }

void list_devices(dev_context* devs, int n_devices) {
	pcap_if_t* d;
	int i;
	for(i=0; i < n_devices; i++) {
		if(!devs[i].pcap_handle) continue;
		printf("%s", devs[i].d->name);
		if(i != n_devices - 1)
			printf(", ");
	}
}

void list_all_devices() {
	pcap_if_t *alldevs;
	int i = 0;
	
	char errbuf[PCAP_ERRBUF_SIZE];
	if(pcap_findalldevs(&alldevs, errbuf) == -1) {
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
	
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
}

void device_set_filter(dev_context *dev, char* filter) {
	if(!dev->pcap_handle) return;
	struct bpf_program fcode;
	bpf_u_int32 netmask;
	
	#ifdef _WIN32
		if(dev->d->addresses != NULL)
			/* Retrieve the mask of the first address of the interface */
			netmask=((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
		else
			/* If the interface is without addresses we suppose to be in a C class network */
			netmask=0xffffff;
	#else
		if (!dev->d->addresses->netmask)
			netmask = 0;
		else
			netmask = ((struct sockaddr_in *)(dev->d->addresses->netmask))->sin_addr.s_addr;
	#endif
	
	//compile the filter
	if (pcap_compile(dev->pcap_handle, &fcode, filter, 1, netmask) <0 )
	{
		fprintf(stderr,"\nUnable to compile the packet filter. Check the syntax.\n");
		return;
	}
	
	//set the filter
	if (pcap_setfilter(dev->pcap_handle, &fcode)<0)
	{
		fprintf(stderr,"\nError setting the filter.\n");
		return;
	}
}

int try_open_device(dev_context* dev) {
	char errbuf[PCAP_ERRBUF_SIZE];
	
	// BUG: potential bug, using same alldevs but device status might have changed,
	//		should create new alldevs, not remove old one cuz other dev contexts might get
	//		corrupted. So should use list of alldevs or something like that
	if(!alldevs) {
		if(pcap_findalldevs(&alldevs, errbuf) == -1) {
			fprintf(stderr,"Critical error in pcap_findalldevs: %s\n", errbuf);
			exit(1);
		}
	}
	
	pcap_if_t* d;
	pcap_t* h;
	for(d=alldevs; d; d=d->next) {
		if(!strcmp(d->name, dev->name)) {
			
			if ((h = pcap_open_live(d->name, 65536,1,1000,errbuf)) == NULL) {
				fprintf(stderr,"\nUnable to open the adapter. %s is not supported by libpcap, skipping !\n", d->name);
				break;
			}
			
			if(pcap_datalink(h) != DLT_EN10MB) {
				fprintf(stderr,"\n%s is not using ethernet stack, skipping !\n", d->name);
				pcap_close(h);
				break;
			}
			
			dev->pcap_handle = h;
			dev->d = d;
			return 1;
		}
	}
	return 0;
}


void free_devices(dev_context* dev, int n_devices) {
	free(dev);
	n_devices_in_use -= n_devices;
	if(n_devices_in_use <= 0) {
		pcap_freealldevs(alldevs);
		alldevs = 0;
		n_devices_in_use = 0;
	}
}

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
	for(t=strtok(devs, ","); t; t=strtok(NULL, ","), num_devs++);
	
	dev_context* dc = (dev_context*)malloc(sizeof(dev_context)*num_devs);
	
	int loaded_devices = 0;
	// iterate devices in array
	strcpy(devs,devlist);
	for(i=0,t=strtok(devs, ","); t && i < num_devs; t=strtok(0, ","), i++) {

		u_int netmask;
		
		dc[i].pcap_handle = 0;
		strcpy(dc[i].name, t);
		
		if(!try_open_device(&dc[i])) {
			printf("warning: interface '%s' not found\n", t);
			continue;
		}
		
		loaded_devices++;
	}
	
	free(devs);
	*n_devices = num_devs;
	
	return dc;
}
