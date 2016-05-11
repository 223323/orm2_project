#ifndef PACKET_H
#define PACKET_H

#include "network_layers.h"

// packet with this signature is valid packet
#define SIGNATURE 0x12343210

#define PACKET_HEADER_SIZE (sizeof(u_int)+sizeof(pkt_type)+sizeof(int))

typedef enum _pkt_type {
	pkt_type_ack,
	pkt_type_data,
	pkt_type_init,
	pkt_type_eof
} pkt_type;

typedef struct _Packet {
	
	u_int signature;
	pkt_type type;
	int size;
	
	union {
		struct IntroPacket {
			int file_size;
			char filename[100];
		} init;
		struct DataPacket {
			int offset;
			int size;
			char bytes[UDP_PACKET_DATA_SIZE-16];
		} data;
	};
	
} Packet;

int reliably_send_packet_udp(dev_context* dev, Packet* pkt, mac_address mac, ip_address ip, int port);
int reconnect(dev_context* dev, int *should_give_up);


#endif
