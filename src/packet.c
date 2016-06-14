#include "packet.h"
#include "devices.h"
#include "network_layers.h"
#include <stdlib.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#define NUM_TRIES 2
#include <unistd.h>
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
			clock_gettime(CLOCK_MONOTONIC,  &ts);
			elapsed = ts.tv_sec + (double)ts.tv_nsec / 1e9;
			// wait for ack
			const u_char * data = pcap_next(dev->pcap_handle, &hdr);
			udp_packet* udp_pkt = (udp_packet*)data;
			if(!validated_packet(udp_pkt)) continue;
			
			if(!validate_ip(dev,udp_pkt)) continue;

			Packet* pkt = (Packet*)udp_pkt->data;

			if(pkt->type == pkt_type_ack && pkt->id == id) {
				return 1;
				break;
			}

		}
	}
	return 0;
}

char validate_ip(dev_context*dev, udp_packet* udp) {
	int i;
	for(i=0; i < 4; i++) {
		if((u_char)dev->addr.sa_data[i+2] != (u_char)udp->ip.daddr.bytes[i]) {
			return 0;
		}
	}
	return 1;
}


void reply_ack(dev_context*dev, udp_packet* udp) {
	Packet ack_pkt;
	ack_pkt.signature = SIGNATURE;
	ack_pkt.type = pkt_type_ack;
	Packet *reply_to_packet = (Packet*)udp->data;
	ack_pkt.id = reply_to_packet->id;
	reply_packet(dev, udp, (char*)&ack_pkt, PACKET_HEADER_SIZE);
}
