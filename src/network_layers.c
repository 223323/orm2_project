#include "network_layers.h"
#include "devices.h"
#include <pcap.h>
#include <string.h> // strtok

// get mac
#include <unistd.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <assert.h>
#include <stdlib.h>
#include "packet.h"

#define debug(x)

void calculate_ip_header_crc(ip_header* hdr) {
	u_short* s = (u_short*)hdr;
	hdr->crc = 0;
	int len = sizeof(ip_header);
	int i;

	int accum = 0;
	for(i=0; i < len/2; i++) {
		accum += s[i];
	}

	while( accum >> 16 )
		accum = (accum >> 16) + (accum & 0xffff);
	hdr->crc = (~accum) & 0xffff;
}

/*
**************************************************************************
Function: udp_sum_calc()
Description: Calculate UDP checksum
***************************************************************************
*/
u_short udp_sum_calc(u_short len_udp, u_char src_addr[], u_char dest_addr[], int padding, u_char buff[])
{
	u_short prot_udp=17;
	u_short padd=0;
	u_short word16;
	int i;
	unsigned int sum;

	// Find out if the length of data is even or odd number. If odd,
	// add a padding byte = 0 at the end of packet
	if (padding&1==1){
		padd=1;
		buff[len_udp]=0;
	}

	//initialize sum to zero
	sum=0;

	// make 16 bit words out of every two adjacent 8 bit words and
	// calculate the sum of all 16 vit words
	for (i=0;i<len_udp+padd;i=i+2){
		word16 =(((u_short)buff[i]<<8)&0xFF00)+(buff[i+1]&0xFF);
		sum = sum + (u_int)word16;
	}
	// add the UDP pseudo header which contains the IP source and destinationn addresses
	for (i=0;i<4;i=i+2){
		word16 =(((u_short)src_addr[i]<<8)&0xFF00)+(src_addr[i+1]&0xFF);
		sum=sum+ (u_int)word16;
	}
	for (i=0;i<4;i=i+2){
		word16 =(((u_short)dest_addr[i]<<8)&0xFF00)+(dest_addr[i+1]&0xFF);
		sum=sum+(u_int)word16;
	}
	// the protocol number and the length of the UDP packet
	sum = sum + prot_udp + len_udp;

	// keep only the last 16 bits of the 32 bit calculated sum and add the carries
    	while (sum>>16)
			sum = (sum & 0xFFFF)+(sum >> 16);

	// Take the one's complement of sum
	sum = ~sum;

	return ((u_short) sum);
}

char hex_digit_to_num(char d) {
	if(d >= '0' && d <= '9') return d-'0';
	if(d >= 'A' && d <= 'F') return d-'A'+10;
	return d-'a'+10;
}

mac_address str2mac(const char* mac_str) {
	int i=0;
	mac_address mac;
	char m[50];
	strcpy(m, mac_str);
	char* tok = strtok(m, ":");
	do {
		u_char byte = 0;
		while(*tok) {
			byte <<= 4;
			byte |= hex_digit_to_num(*tok++);
		}
		mac.bytes[i++] = byte;
	} while((tok = strtok(NULL, ":")) && i < 6);

	return mac;
}

void get_mac_address(char* devname, mac_address* addr) {
	struct ifreq ifr;
	int i;
	strcpy(ifr.ifr_name, devname);
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	ioctl(s, SIOCGIFHWADDR, &ifr);
	for(i=0; i < 6; i++) {
		addr->bytes[i] = ifr.ifr_hwaddr.sa_data[i];
	}
	close(s);
}

int make_packet(udp_packet* pkt,
				mac_address smac,
				mac_address dmac,
				ip_address sip,
				ip_address dip,
				int sport,
				int dport,
				char* pkt_data,
				int data_length) {

	int packet_length;

	eth_header *eth_hdr = &pkt->eth;

	eth_hdr->smac = smac;
	eth_hdr->dmac = dmac;

	eth_hdr->proto_type = htons(0x0800);

	assert(sizeof(eth_header) == 14);
	packet_length = sizeof(eth_header);

	ip_header *ip_hdr = &pkt->ip;
	ip_hdr->ver_ihl = 0x45; // version + header length
	ip_hdr->tos = 0x00;
	ip_hdr->tlen = sizeof(ip_header); // total length (header + encapsulated data)
	ip_hdr->identification = htons(4556);
	ip_hdr->flags_fo = htons(0x4000);
	ip_hdr->ttl = 64;
	ip_hdr->proto = 17;

	ip_hdr->saddr = sip;
	ip_hdr->daddr = dip;
	// ip_hdr->op_pad = 0;
	// ip_hdr->crc = 0;

	assert(sizeof(ip_header) == 20);
	memcpy(pkt->data, pkt_data, data_length);

	udp_header* udp_hdr = &pkt->udp;

	assert((long)&pkt->udp - (long)&pkt->eth == sizeof(ip_header) + sizeof(eth_header));

	udp_hdr->sport = htons(sport); // optional (0 if not used)
	udp_hdr->dport = htons(dport);

	assert(sizeof(udp_header) == 8);
	short udp_len = sizeof(udp_header) + data_length;
	udp_hdr->len = htons(udp_len);

	udp_hdr->crc = 0;

	// debug(printf("crc udp\n"));
	u_short udp_sum = udp_sum_calc(udp_len, (u_char*)&(ip_hdr->saddr),
		(u_char*)&(ip_hdr->daddr), udp_len, (u_char*)udp_hdr);
	udp_hdr->crc = htons(udp_sum);


	ip_hdr->tlen = htons(sizeof(ip_header) + sizeof(udp_header) + data_length);

	// debug(printf("crc ip\n"));
	calculate_ip_header_crc(ip_hdr);

	packet_length = sizeof(eth_header) + sizeof(ip_header) + sizeof(udp_header) + data_length;
	return packet_length;
}

void dump_packet(udp_packet* pkt, char* filename) {
	int pkt_len = htons( pkt->ip.tlen ) + sizeof(eth_header);
	FILE* f = fopen(filename, "w");
	fwrite(pkt, 1, pkt_len, f);
	fclose(f);
}

void dump_mac(mac_address mac) {
	int i;
	for(i=0; i < 6; i++) {
		printf("%.2X", (int)mac.bytes[i]);
		if(i != 5)
			printf(":");
	}
}

void send_packet(dev_context* dev, mac_address dmac, ip_address dip, u_int dport, char *data, int data_length) {
	debug(printf("getting ip address ... \n"));
	int i;
	// get source ip addr
	ip_address ip_addr;
	struct pcap_addr* adr;
	for(adr = dev->d->addresses; adr; adr=adr->next) {
		struct sockaddr* addr = adr->addr;
		if(addr->sa_family == AF_INET) {
			char* ip = addr->sa_data+2;
			for(i=0; i < 4; i++) {
				ip_addr.bytes[i] = ip[i];
			}
			break;
		}
	}

	debug(
		printf("ip address is: ");
		for(i=0; i < 4; i++) {
			printf("%d", ip_addr.bytes[i]);
			if(i != 3)
				printf(".");
		}
	)

	mac_address mac_addr;
	debug(printf("\ngetting mac address ... "));
	get_mac_address(dev->d->name, &mac_addr);
	debug(
		printf("\nmac address is: ");
		for(i=0; i < 6; i++) {
			printf("%0.2x", mac_addr.bytes[i]);
			if(i != 5)
				printf(":");
		}

	printf("\n");
	)

	// debug(printf("sending packet ...\n"));

	udp_packet pkt;
	int pkt_len = make_packet(&pkt, mac_addr, dmac, ip_addr, dip, rand()%5000+1024, dport, data, data_length);
	pcap_sendpacket(dev->pcap_handle, (const u_char*)&pkt, pkt_len);

}

void reply_packet(dev_context* dev, udp_packet* pkt, char *data, int data_length) {
	send_packet(dev, pkt->eth.smac, pkt->ip.saddr, htons(pkt->udp.sport), data, data_length);
}

int validated_packet(udp_packet *pkt) {
	if(!pkt) return 0;
	if(pkt->ip.ver_ihl != 0x45) {
		printf("received data with ip.ver_ihl = %d not supported, skipping !\n", (int)pkt->ip.ver_ihl);
		return 0;
	}
	int data_len = packet_get_data_length(pkt);
	Packet *mypkt = (Packet*)pkt->data;
	if (!(data_len >= 8 && mypkt->signature == SIGNATURE && data_len <= UDP_PACKET_DATA_SIZE)) return 0;

	int udp_len = htons(pkt->udp.len);
	u_short pkt_crc = pkt->udp.crc;
	pkt->udp.crc = 0;
	u_short udp_checksum = udp_sum_calc(udp_len, pkt->ip.saddr.bytes, pkt->ip.daddr.bytes, udp_len, (u_char*)&pkt->udp);

	if(htons(udp_checksum) != pkt_crc) return 0;

	return 1;
}

int packet_get_data_length(udp_packet *pkt) {
	return htons(pkt->udp.len) - sizeof(udp_header);
}

// http://www.hackersdelight.org/hdcodetxt/crc.c.txt
unsigned int crc32c(unsigned char *message) {
   int i, j;
   unsigned int byte, crc, mask;
   static unsigned int table[256];

   /* Set up the table, if necessary. */

   if (table[1] == 0) {
      for (byte = 0; byte <= 255; byte++) {
         crc = byte;
         for (j = 7; j >= 0; j--) {    // Do eight times.
            mask = -(crc & 1);
            crc = (crc >> 1) ^ (0xEDB88320 & mask);
         }
         table[byte] = crc;
      }
   }

   /* Through with table setup, now calculate the CRC. */

   i = 0;
   crc = 0xFFFFFFFF;
   while ((byte = message[i]) != 0) {
      crc = (crc >> 8) ^ table[(crc ^ byte) & 0xFF];
      i = i + 1;
   }
   return ~crc;
}
