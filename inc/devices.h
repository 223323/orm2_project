#ifndef DEVICES_H
#define DEVICES_H

#include <pcap.h>
typedef struct _dev_context {
	int processing_block_num;
	pcap_t *pcap_handle;
	pcap_if_t* d;
	int last_id;
} dev_context;

dev_context* load_devices(char* devlist, int *n_devices);
pcap_if_t* get_alldevs();
void list_devices(dev_context* devs, int n_devices);
void list_all_devices();


#endif
