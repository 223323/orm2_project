#include "devices.h"
#include "network_layers.h"
#include <time.h>

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

// --------- basic listen with filters
void setup_listen(char* dev, char* filter) {
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i=0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;
	struct bpf_program fcode;
	
	int n_devs = 0;
	dev_context *devs = load_devices(dev, &n_devs);
	
	if(n_devs == 0) return;
	
	
	adhandle = devs->pcap_handle;
	d = devs->d;

	//compile the filter
	if (pcap_compile(adhandle, &fcode, filter, 1, netmask) <0 )
	{
		fprintf(stderr,"\nUnable to compile the packet filter. Check the syntax.\n");
		return;
	}
	
	//set the filter
	if (pcap_setfilter(adhandle, &fcode)<0)
	{
		fprintf(stderr,"\nError setting the filter.\n");
		return;
	}
	
	printf("\nlistening on %s...\n", d->description);

	pcap_freealldevs(get_alldevs());
	/* start the capture */
	pcap_loop(adhandle, 0, packet_handler, NULL);
}

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct tm *ltime;
	char timestr[16];
	ip_header *ih;
	udp_header *uh;
	u_int ip_len;
	u_short sport,dport;
	time_t local_tv_sec;

	/*
	 * unused parameter
	 */
	(void)(param);

	/* convert the timestamp to readable format */
	local_tv_sec = header->ts.tv_sec;
	ltime=localtime(&local_tv_sec);
	strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);

	/* print timestamp and length of the packet */
	printf("%s.%.6d len:%d ", timestr, (int)header->ts.tv_usec, (int)header->len);

	/* retireve the position of the ip header */
	ih = (ip_header *) (pkt_data +
		14); //length of ethernet header

	/* retireve the position of the udp header */
	ip_len = (ih->ver_ihl & 0xf) * 4;
	uh = (udp_header *) ((u_char*)ih + ip_len);

	/* convert from network byte order to host byte order */
	sport = ntohs( uh->sport );
	dport = ntohs( uh->dport );

	/* print ip addresses and udp ports */
	printf("%d.%d.%d.%d.%d -> %d.%d.%d.%d.%d\n",
		ih->saddr.bytes[0],
		ih->saddr.bytes[1],
		ih->saddr.bytes[2],
		ih->saddr.bytes[3],
		sport,
		ih->daddr.bytes[0],
		ih->daddr.bytes[1],
		ih->daddr.bytes[2],
		ih->daddr.bytes[3],
		dport);
}
