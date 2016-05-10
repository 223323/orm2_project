#include <string.h>
#include <assert.h>
#include <pcap.h>
#include <stdlib.h>
#include "network_layers.h"
#include "devices.h"
#include "queue.h"


void server_thread(dev_context* dev) {
	printf("hello from: %s\n", dev->d->name);
	
	
}

int setup_server(char* devlist) {
	int i=0;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	char packet_filter[] = "ip and udp";
	struct bpf_program fcode;
	
	int n_devices;
	dev_context* devices = load_devices(devlist, &n_devices);
	
	printf("loaded %d devices\n", n_devices);
	printf("loaded devices are: ");
	list_devices(devices,n_devices);
	printf("\n");
	/* start the capture */
	// pcap_loop(adhandle, 0, packet_handler, NULL);
	
	thrd_t *thread = (thrd_t*)malloc(sizeof(thrd_t)*n_devices);
	for(i=0; i < n_devices; i++) {
		thrd_create(&thread[i], (thrd_start_t)server_thread, &devices[i]);
	}
	
	// for(i=0; i < n_devices; i++) {
		// thrd_join(thread[i],0);
	// }
	
	
	// ----------- building packet
	
	/*
	int pkt_len = 0;
	u_char pkt_buff[200];
	u_char pkt_data[200];
	{
		
		eth_header *eth_hdr = (eth_header*)pkt_buff;

		eth_hdr->smac = MAC(00:0f:60:06:23:0a);
		eth_hdr->dmac = MAC(00:90:a2:cd:d4:49);

		eth_hdr->proto_type = htons(0x0800);
		
		assert(sizeof(eth_header) == 14);
		pkt_len += sizeof(eth_header);
		
		ip_header *ip_hdr = (ip_header*)(pkt_buff + pkt_len);
		ip_hdr->ver_ihl = 0x46; // version + header length
		ip_hdr->tos = 0x00;
		ip_hdr->tlen = sizeof(ip_header); // total length (header + encapsulated data)
		ip_hdr->identification = htons(4556);
		ip_hdr->flags_fo = htons(0x4000);
		ip_hdr->ttl = 64;
		ip_hdr->proto = 17;
		
		ip_hdr->saddr = IP_ADDR(10.0.0.49);
		ip_hdr->daddr = IP_ADDR(10.0.0.1);
		ip_hdr->op_pad = 0;
		// ip_hdr->crc = 0;
		
		// packet data to send
		strcpy(pkt_data, "Hello World\n");
		int pkt_data_len = strlen(pkt_data);
		
		pkt_len += sizeof(ip_header);
		
		udp_header* udp_hdr = (udp_header*)(pkt_buff + pkt_len);
		
		
		udp_hdr->sport = htons(2000); // optional (0 if not used)
		udp_hdr->dport = htons(5000);
		
		short udp_len = sizeof(udp_header) + strlen(pkt_data);
		udp_hdr->len = htons(udp_len);
		
		udp_hdr->crc = 0;
		pkt_len += sizeof(udp_header);
		strcpy(pkt_buff+pkt_len, pkt_data);
		printf("crc udp\n");
		u_short udp_sum = udp_sum_calc(udp_len, (u_char*)&(ip_hdr->saddr), 
			(u_char*)&(ip_hdr->daddr), udp_len, (u_char*)udp_hdr);
		udp_hdr->crc = htons(udp_sum);
		
		
		pkt_len += pkt_data_len;
		ip_hdr->tlen = (long)pkt_buff + (long)pkt_len - (long)ip_hdr;
		ip_hdr->tlen = htons(ip_hdr->tlen);
		
		printf("crc ip\n");
		calculate_ip_header_crc(ip_hdr);

		printf("writing file\n");
		
		FILE* f = fopen("dump.bin", "w");
		fwrite(pkt_buff, 1, pkt_len, f);
		fclose(f);
	}
	*/
	// ---------------
	
	// ------- using udp packet struct
	udp_packet pkt;
	int pkt_len = make_packet(&pkt, 
		MAC(00:0f:60:06:23:0a),
		MAC(00:90:a2:cd:d4:49),
		IP_ADDR(10.0.0.49),
		IP_ADDR(10.0.0.1),
		2000,
		5000, "nikolice bre :D\n");
	// -------
	
	dump_packet(&pkt, "dump.bin");
	
	send_packet(&devices[0], MAC(00:90:a2:cd:d4:49), IP_ADDR(10.0.0.1), 5000, "hehhehe");
	
	// printf("pcap_sendpacket\n");
	
	// int res;
	// res = pcap_sendpacket(devices[0].pcap_handle, pkt_buff, pkt_len);
	// res = pcap_sendpacket(devices[0].pcap_handle, (const u_char*)&pkt, pkt_len);
	
	// if(res == 0) {
		// printf("Success !!\n");
	// } else {
		// pcap_perror(devices[0].pcap_handle, "sendpacket");
		// printf("FAIL\n");
	// }
	
}
