#include "packet.h"
#include "devices.h"
#include "network_layers.h"
#include <unistd.h>
#define NUM_TRIES 3

/*
	after not receving ack for 3 tries, assume disconnected
	and return false
*/
int reliably_send_packet_udp(dev_context* dev, Packet* pkt, mac_address mac, ip_address ip, int port) {
	int succeeded = 0;
	int i;
	struct pcap_pkthdr hdr;
	for(i=0; i < NUM_TRIES; i++) {
		
		send_packet(dev, mac, ip, port, (char*)pkt, pkt->size);
		
		// wait for ack
		const u_char * data = pcap_next(dev->pcap_handle, &hdr);
		udp_packet* udp_pkt = (udp_packet*)data;
		if(!validated_packet(udp_pkt)) continue;
		
		Packet* pkt = (Packet*)udp_pkt->data;
		
		if(pkt->type == pkt_type_ack) {
			succeeded = 1;
			break;
		}
	}
	
	return succeeded;
}

int reconnect(dev_context* dev, int *should_give_up) {
	while(!*should_give_up) {
		if(try_open_device(dev)) return 1;
		sleep(1);
	}
	return 0;
}
