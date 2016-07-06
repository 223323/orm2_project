#ifndef PACKET_H
#define PACKET_H

#include "network_layers.h"




typedef enum _pkt_type {
	pkt_type_ack=1,
	pkt_type_data,
	pkt_type_init,
	pkt_type_control,
	pkt_type_eof
} pkt_type;

typedef struct _Packet {
	#define PACKET_HEADER_SIZE (sizeof(u_int)+sizeof(pkt_type)+sizeof(int)+sizeof(int))
	// packet with this signature is valid packet
	#define SIGNATURE 0x12343210
	u_int signature;
	pkt_type type;
	int size;
	int id;
	union {
		struct IntroPacket {
			#define PACKET_INIT_HEADER_SIZE (sizeof(size_t))
			size_t file_size;
			char filename[100];
			int packet_size;
		} init;
		struct DataPacket {
			#define PACKET_DATA_HEADER_SIZE (sizeof(size_t)+sizeof(int))
			#define PACKET_DATA_MAX_BYTES (UDP_PACKET_DATA_SIZE-500)
			size_t offset;
			int size;
			char bytes[UDP_PACKET_DATA_SIZE-500];
		} data;
		int ack_state;
		int packets_in_row;
	};

} Packet;

int reliably_send_packet_udp(dev_context* dev, Packet* pkt, mac_address mac, ip_address ip, int port);
void reply_ack(dev_context*dev, udp_packet* udp);
char validate_ip(dev_context*dev, udp_packet* udp);
Packet packet_init(pkt_type type);
#endif
