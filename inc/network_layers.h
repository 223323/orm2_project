#ifndef NETWORK_LAYERS_H
#define NETWORK_LAYERS_H

#include <pcap.h>
#include <arpa/inet.h>
#include "devices.h"

/* 4 bytes IP address */
typedef struct ip_address
{
	union {
		u_char bytes[4];
		u_int32_t ip;
	};
} ip_address;

typedef struct mac_address
{
	u_char bytes[6];
} __attribute__((packed)) mac_address;

/* IPv4 header */

typedef struct ip_header
{
	u_char	ver_ihl;		// Version (4 bits) + Internet header length (4 bits)
	u_char	tos;			// Type of service 
	u_short tlen;			// Total length 
	u_short identification; // Identification
	u_short flags_fo;		// Flags (3 bits) + Fragment offset (13 bits)
	u_char	ttl;			// Time to live
	u_char	proto;			// Protocol
	u_short crc;			// Header checksum
	ip_address	saddr;		// Source address
	ip_address	daddr;		// Destination address
	u_int	op_pad;			// Option + Padding
} ip_header;

/* UDP header*/
typedef struct udp_header
{
	u_short sport;			// Source port
	u_short dport;			// Destination port
	u_short len;			// Datagram length
	u_short crc;			// Checksum
} __attribute__((packed)) udp_header;

typedef struct eth_header {
	mac_address dmac;
	mac_address smac;
	u_short proto_type;
} __attribute__((packed)) eth_header; 

u_short udp_sum_calc(u_short len_udp, u_char src_addr[], u_char dest_addr[], int padding, u_char buff[]);
mac_address str2mac(const char* mac_str);
// ip_address str2ip(const char* ip_str);
void calculate_ip_header_crc(ip_header* hdr);

//#define MAC(s,m) *(u_short*)s = htons(m >> 32); *(u_long*)(s+2) = htonl(m & 0xffffffff);
#define MAC(m) str2mac(#m)
#define IP_ADDR(a) (ip_address){ .ip = inet_addr(#a) } //str2ip(#a)

typedef struct udp_packet {
	eth_header eth;
	ip_header ip;
	udp_header udp;
	u_char data[1500];
} __attribute__((packed)) udp_packet;

void get_mac_address(char* devname, mac_address* addr);

int make_packet(udp_packet* pkt, 
				mac_address smac,
				mac_address dmac,
				ip_address sip,
				ip_address dip,
				int sport,
				int dport,
				char* pkt_data);
void dump_packet(udp_packet* pkt, char* filename);
void send_packet(dev_context* dev, mac_address dmac, ip_address dip, u_int dport, char *data);

#endif
