#ifndef PACKET_H
#define PACKET_H

#include "network_layers.h"

// packet with this signature is valid packet
#define SIGNATURE 0x12343210

typedef enum _pkt_t {
	ack,
	data,
	intro
} pkt_t;

typedef struct _Packet {
	
	u_int signature;
	pkt_t type;
	
	union {
		struct IntroPacket {
			int file_size;
			char filename[100];
			int num_parts;
			int part_size;
		} intro;
		char data[UDP_PACKET_DATA_SIZE-16];
	};
	
} Packet;


#endif
