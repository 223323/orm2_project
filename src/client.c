#include "tinycthread.h"
#include "devices.h"
#include <stdlib.h>

void client_thread(dev_context *dev) {
	
}

int setup_client(char *devlist, char *dmac, char *dip, int dport, char *transfer_file) {
	
	int i;
	int n_devices;
	dev_context* devices = load_devices(devlist, &n_devices);
	
	thrd_t *thread = (thrd_t*)malloc(sizeof(thrd_t)*n_devices);
	
	for(i=0; i < n_devices; i++) {
		
		thrd_create(&thread[i], (thrd_start_t)client_thread, &devices[i]);
	}
}
