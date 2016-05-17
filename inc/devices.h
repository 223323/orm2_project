#ifndef DEVICES_H
#define DEVICES_H

#include <pcap.h>
typedef struct _dev_context {
	char name[15];
	pcap_t *pcap_handle;
	pcap_if_t* d;
} dev_context;

dev_context* load_devices(char* devlist, int *n_devices);
pcap_if_t* get_alldevs();
void list_devices(dev_context* devs, int n_devices);
void list_all_devices();
void device_set_filter(dev_context *dev, char* filter);
int try_open_device(dev_context* dev);
void free_devices(dev_context* dev, int n_devices);
int device_reopen(dev_context* dev, int *should_give_up);
#endif
