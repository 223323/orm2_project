#include "packet.h"
#include "devices.h"
#include "network_layers.h"
#include <stdlib.h>
#include <time.h>
#include <stdio.h>
#define NUM_TRIES 2

/*
	after not receving ack for N tries, assume disconnected
	and return false
*/
int reliably_send_packet_udp(dev_context* dev, Packet* pkt, mac_address mac, ip_address ip, int port) {
	int i;
	struct pcap_pkthdr hdr;
	int id = pkt->id = rand()%10000;
	struct timespec ts;
	struct timespec ts2;
	double elapsed=0;
	double elapsed1=0;
	ts.tv_sec = ts.tv_nsec = 0;
	for(i=0; i < NUM_TRIES; i++) {

		send_packet(dev, mac, ip, port, (char*)pkt, pkt->size);

		clock_gettime(CLOCK_MONOTONIC,  &ts2);
		elapsed1 = ts2.tv_sec + (double)ts2.tv_nsec / 1e9;
		while(elapsed - elapsed1 < 0.5) {
		// clock_t clk = clock();
		// while(clock() - clk < CLOCKS_PER_SEC/2) {
			clock_gettime(CLOCK_MONOTONIC,  &ts);
			elapsed = ts.tv_sec + (double)ts.tv_nsec / 1e9;
			// printf("%d\n", (int)clock());
			// wait for ack
			const u_char * data = pcap_next(dev->pcap_handle, &hdr);
			udp_packet* udp_pkt = (udp_packet*)data;
			if(!validated_packet(udp_pkt)) continue;

			Packet* pkt = (Packet*)udp_pkt->data;

			if(pkt->type == pkt_type_ack && pkt->id == id) {
				return 1;
				break;
			}
			
		}
		printf("wtf\n");
	}

	return 0;
}

void reply_ack(dev_context*dev, udp_packet* udp) {
	Packet ack_pkt;
	ack_pkt.signature = SIGNATURE;
	ack_pkt.type = pkt_type_ack;
	Packet *reply_to_packet = (Packet*)udp->data;
	ack_pkt.id = reply_to_packet->id;
	reply_packet(dev, udp, (char*)&ack_pkt, PACKET_HEADER_SIZE);
}
