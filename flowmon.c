#include <sys/socket.h>
#include <linux/if_ether.h>
//#include <linux/ip.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <time.h>
#include <linux/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/types.h>
#include <string.h>
#include <stdbool.h>

//#define IP_MF 0x2000	// IP MF flag
//#define IP_DF 0x4000	// IP DF flag

#define MEMSET(buffer,rpcode,size) { cleanIdx = 0; while (cleanIdx<size) { buffer[cleanIdx] = rpcode; cleanIdx++;} }

struct flowhdr{
	time_t initTime;
	unsigned long long pktCnt;
	double timeItv;
	unsigned short  sport, dport;
	unsigned long src,dst;
	unsigned long tcpId;  // Not used
	struct flowhdr *next;
	struct flowhdr *prev;
	struct flowhdr *datnxt;
	struct flowhdr *datprv;
	bool finYet;
};

struct ipfrag{
	__be16 id;
	__be32 saddr;
	__be32 daddr;
	struct tcphdr *fraghdr;
};

int main ()
{
	struct ethhdr *epkt;
	struct iphdr *ippkt;
	struct tcphdr *tcppkt;

	clock_t tstart, tend;
	double res;

	unsigned long int flowCnt, loopCnt;

	unsigned char buffer[65536];
	struct ipfrag *fragB[100];	// IP fragment Buffer size 100

	int cleanIdx;

	MEMSET( fragB, 0, sizeof(fragB));
	int indx;
	char fldat[1000];		//filing data buffer MAX size = 100 bytes
	char tamperdat[100];		// for temperarily store data

	struct flowhdr *froot;   // root node initialize 
				 // froot is an empty node as a root
	struct flowhdr *handler; // handler for malloc release
	
	FILE *log;

	struct sockaddr_in convertor;

	froot = (struct flowhdr *) malloc(sizeof(struct flowhdr));

	froot->pktCnt = 0;
	froot->initTime = 0;
	froot->timeItv = 0;
	froot->sport = 0;
	froot->dport = 0;
	froot->src = 0;
	froot->dst = 0;
	froot->tcpId = 0;
	froot->finYet = false;
	froot->next = froot;
	froot->prev = froot;
	froot->datnxt = froot;
	froot->datprv = froot;

	int sock;
	int pktSize;

	
	//char *iface;
	//iface = "eth0";
	//setsockopt( sock, SOL_SOCKET, SO_BINDTODEVICE, iface, 4);	

	struct flowhdr *tmp;

	loopCnt = 0;

	while(1) {

		tstart = clock();
		tend = tstart;
		res = 0;

		for (; res < 0.2 ; tend = clock()) // 200 ms Interval
		{
			if ( (sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)
			{	printf("ERROR:  Socket Creation Failed");
				return 0;
			}

			MEMSET(buffer,0,65536);

			pktSize = recv( sock, buffer, 65536, 0);
			res += ((double) (tend-tstart))/CLOCKS_PER_SEC; // time interval
			//printf("%f\n",res);
			
			if (pktSize < 42)	// Eth 14 + IPv4 20 + TCP 8
				continue;

			epkt = (struct ethhdr *) buffer;
			if ( epkt->h_proto != htons(ETH_P_IP) ) // Eth
				continue;
			ippkt = (struct iphdr *) (buffer + 14); // IPv4
			if ( ippkt->protocol != 6 )            // NOTE: Please ensure NIC in promiscus OFF mode
				continue;

			// Check if frag enabled?
			// Yes!
			// 	Check if already registered in fragB?
			// 	Yes!
			// 	ADD A TCP HEADER
			// 		Check if the last packet?
			//		Yes!
			//		Remove from the reg, & re-arrange the array
			//	Nop!
			//	Register it in fragB!
			if ( (ippkt->frag_off & htons(IP_DF)) == 0 )
			{	
				indx = 0;
				for (; fragB[indx] != 0; indx++)
					if (fragB[indx]->id == ippkt->id && fragB[indx]->saddr == ippkt->saddr && fragB[indx]->daddr == ippkt->daddr)
						break;
				if ( fragB[indx] != 0)
				{	tcppkt = (struct tcphdr *) memcpy( buffer + 14 + ippkt->ihl*4, fragB[indx]->fraghdr, sizeof(struct tcphdr));
					free(fragB[indx]->fraghdr);
					
					if ( (ippkt->frag_off & htons(IP_MF)) == 0 )
						for(; fragB[indx] != 0 && indx < 100; indx++)
							fragB[indx] = fragB[indx + 1];		}
				else
				{
					indx = 0;
					for (; fragB[indx] != 0; indx++);
					fragB[indx]->id = ippkt->id;
					fragB[indx]->saddr = ippkt->saddr;
					fragB[indx]->daddr = ippkt->daddr;
					fragB[indx]->fraghdr = (struct tcphdr *) malloc(sizeof(struct tcphdr));

					tcppkt = (struct tcphdr *) (buffer + 14 + ippkt->ihl * 4);

					fragB[indx]->fraghdr->source = tcppkt->source;
					fragB[indx]->fraghdr->dest = tcppkt->dest;
					fragB[indx]->fraghdr->seq = tcppkt->seq;
					fragB[indx]->fraghdr->ack_seq = tcppkt->ack_seq;

					fragB[indx]->fraghdr->res1 = tcppkt->res1;
					fragB[indx]->fraghdr->doff = tcppkt->doff;
					fragB[indx]->fraghdr->fin = tcppkt->fin;
					fragB[indx]->fraghdr->syn = tcppkt->syn;
					fragB[indx]->fraghdr->rst = tcppkt->rst;
					fragB[indx]->fraghdr->psh = tcppkt->psh;
					fragB[indx]->fraghdr->ack = tcppkt->ack;
					fragB[indx]->fraghdr->urg = tcppkt->urg;
					fragB[indx]->fraghdr->ece = tcppkt->ece;
					fragB[indx]->fraghdr->cwr = tcppkt->cwr;

					fragB[indx]->fraghdr->window = tcppkt->window;
					fragB[indx]->fraghdr->check = tcppkt->check;
					fragB[indx]->fraghdr->urg_ptr = tcppkt->urg_ptr;
				}
			}
			else
				tcppkt = (struct tcphdr *) (buffer + 14 + ippkt->ihl * 4);
			// TCP Check
			tmp = froot->next;
			while (tmp != froot && (ippkt->saddr != tmp->src || ippkt->daddr != tmp->dst || tcppkt->dest != tmp->dport || tcppkt->source != tmp->src ))
				tmp = tmp->next;
			if (tmp == froot && tcppkt->syn != 1 && tcppkt->fin != 1)	// It's a mis-recv pkt. drop
				continue;
			if (tmp == froot && tcppkt->syn == 1 && tcppkt->ack != 1 && tcppkt->fin != 1)    // It's a new flow. So Create & Append a new structure.
			{	froot->prev->next = (struct flowhdr *) malloc(sizeof(struct flowhdr));
				if (tmp->prev->next == NULL)
				{	printf("ERROR:  malloc Failed");
					return 0;	}
				froot->prev->next->next = froot;
				froot->prev->next->prev = froot->prev;
				froot->prev = froot->prev->next;
				// Initialize
				froot->prev->datnxt = froot->prev;
				froot->prev->datprv = froot->prev;
				froot->prev->src = ippkt->saddr;
				froot->prev->dst = ippkt->daddr;
				froot->prev->sport = tcppkt->source;
				froot->prev->dport = tcppkt->dest;
				froot->prev->initTime = time(NULL);
				froot->prev->finYet = false;
				froot->prev->timeItv = 0;
				froot->prev->tcpId = 0;   // TODO: id pool Maybe?
				froot->prev->pktCnt = pktSize;
			}

			else
				if (tmp == froot && !(tcppkt->syn == 1 && tcppkt->ack != 1 && tcppkt->fin != 1))	// Out-of-Order pkt
					continue;		// Drop
				else					// This is a registered flow.
					if (tcppkt->fin != 1)
						tmp->datprv->pktCnt += pktSize;
					else
					// if Finished.
					{	tmp->datprv->pktCnt += pktSize;
						tmp->datprv->finYet = true;	}     // If so set a fin flag over the last dat block.
				
		}
		
		tmp = froot->next;
		flowCnt = 0;
		while(tmp != froot)
		{	tmp->datprv->timeItv = res;   // Write the res to timeItv for each New-created log block.
			if (tmp->datprv->finYet == false)   // Add an additional flowhdr block for each flow, if the flow hasn't finished.
			{ 
				// Eliminate the Broken flow segment
				if (tmp->datprv->pktCnt < 50 && tmp->datprv == tmp)  // a flow has only ONE dat block
				{							    //   and packet received less than 50
					// Remove such block
					handler = tmp;
					tmp->prev->next = tmp->next;
					tmp->next->prev = tmp->prev;
					tmp = tmp->next;
					free(handler);
					handler = NULL;
					continue;
				}
				tmp->datprv->datnxt = (struct flowhdr *) malloc(sizeof(struct flowhdr));
				if (tmp->datprv->datnxt == NULL)
				{	printf("ERROR:  malloc Failed");
					return 0;	}
			   	tmp->datprv->datnxt->datprv = tmp->datprv;
			   	tmp->datprv->datnxt->datnxt = tmp;
			   	tmp->datprv = tmp->datprv->datnxt;
			   	// initialize
			   	tmp->datprv->next = NULL;
			   	tmp->datprv->prev = NULL;
			   	tmp->datprv->src = tmp->src;
			   	tmp->datprv->dst = tmp->dst;
			   	tmp->datprv->sport = tmp->sport;
			   	tmp->datprv->dport = tmp->dport;
			   	tmp->datprv->finYet = tmp->finYet;
				tmp->datprv->initTime = tmp->initTime;
			   	tmp->datprv->timeItv = 0;
			   	tmp->datprv->pktCnt = 0;
			   	tmp->datprv->tcpId = tmp->tcpId;
				// increase the flow counter
				flowCnt++;
			}
			else
			{
				printf("Saving Finished flow stat");
				// Print & File the finished flows
				log = fopen("flowlog","a");
				MEMSET( fldat, 0, sizeof(fldat));
				strcpy( fldat, "Start Time: ");
				MEMSET( tamperdat, 0, sizeof(tamperdat));
				sprintf( tamperdat, "%ld\n", tmp->initTime);
				strcat( fldat, tamperdat);
				fwrite( fldat, strlen(fldat), 1, log);

				while(tmp->finYet == false)
				{
					// P&F
					MEMSET( fldat, 0, sizeof(fldat));

					if (tmp->timeItv == 0)
					{	printf("ERROR:  Time is 0");
						// set timeItv to a big number
						//  make the throughput near zero
						tmp->timeItv = 999999;
						continue;	}
					strcat( fldat, "source: ");
					MEMSET( tamperdat, 0, sizeof(tamperdat));
					convertor.sin_addr.s_addr = tmp->src;
					sprintf( tamperdat, "%s", inet_ntoa(convertor.sin_addr));
					convertor.sin_addr.s_addr = 0;
					strcat( fldat, tamperdat);

					MEMSET( tamperdat, 0, sizeof(tamperdat));
					sprintf( tamperdat, ": %d\n", ntohs(tmp->sport));
					strcat( fldat, tamperdat);
					
					MEMSET( tamperdat, 0, sizeof(tamperdat));
					convertor.sin_addr.s_addr = tmp->dst;
					sprintf( tamperdat, "dest : %s", inet_ntoa(convertor.sin_addr));
					convertor.sin_addr.s_addr = 0;
					strcat( fldat, tamperdat);

					MEMSET( tamperdat, 0, sizeof(tamperdat));
					sprintf( tamperdat, ": %d\n", ntohs(tmp->dport));
					strcat( fldat, tamperdat);

					MEMSET( tamperdat, 0, sizeof(tamperdat));
					sprintf( tamperdat, "Time Interval: %f\n", tmp->timeItv);
					strcat( fldat, tamperdat);

					MEMSET( tamperdat, 0, sizeof(tamperdat));
					sprintf( tamperdat, "Throughput: %f\n", (float)tmp->pktCnt / tmp->timeItv);
					strcat( fldat, tamperdat);

					fwrite( fldat, strlen(fldat), 1, log);

					// pop the 1st data block
					tmp->datnxt->next = tmp->next;
					tmp->datnxt->prev = tmp->prev;
					tmp->datnxt->datprv = tmp->datprv;
					tmp->datprv->datnxt = tmp->datprv;
					handler = tmp;
					tmp = tmp->datnxt;
					free(handler);
					handler = NULL;
				}
				// Extract the last pack with finYet == true
				// 	 & re-arrange the data-struct
				
				// P&F
				MEMSET( fldat, 0, sizeof(fldat));

				if (tmp->timeItv == 0)
				{	printf("ERROR:  Time is 0");
					// set timeItv to a big number
					//  make the throughput near zero
					tmp->timeItv = 999999;
					continue;	}
				strcat( fldat, "source: ");
				MEMSET( tamperdat, 0, sizeof(tamperdat));
				convertor.sin_addr.s_addr = tmp->src;
				sprintf( tamperdat, "%s", inet_ntoa(convertor.sin_addr));
				convertor.sin_addr.s_addr = 0;
				strcat( fldat, tamperdat);

				MEMSET( tamperdat, 0, sizeof(tamperdat));
				sprintf( tamperdat, ": %d\n", ntohs(tmp->sport));
				strcat( fldat, tamperdat);
				
				MEMSET( tamperdat, 0, sizeof(tamperdat));
				convertor.sin_addr.s_addr = tmp->dst;
				sprintf( tamperdat, "dest : %s", inet_ntoa(convertor.sin_addr));
				convertor.sin_addr.s_addr = 0;
				strcat( fldat, tamperdat);

				MEMSET( tamperdat, 0, sizeof(tamperdat));
				sprintf( tamperdat, ": %d\n", ntohs(tmp->dport));
				strcat( fldat, tamperdat);

				MEMSET( tamperdat, 0, sizeof(tamperdat));
				sprintf( tamperdat, "Time Interval: %f\n", tmp->timeItv);
				strcat( fldat, tamperdat);

				MEMSET( tamperdat, 0, sizeof(tamperdat));
				sprintf( tamperdat, "Throughput: %f\n", (float)tmp->pktCnt / tmp->timeItv);
				strcat( fldat, tamperdat);

				fwrite( fldat, strlen(fldat), 1, log);

				handler = tmp;
				tmp->next->prev = tmp->prev;
				tmp->prev->next = tmp->next;
				tmp = tmp->prev;
				free(handler);
				handler = NULL;

				fclose(log);
			}
			tmp = tmp->next;
		}

		// Show how many unfinished flows still there
		printf("%lu active flows taping...\n", flowCnt);

		// Automatically Exit when all flows are finished, or waiting too long.
		if (flowCnt == 0)
			loopCnt++;
		else
			loopCnt = 0;
		if (loopCnt > 100000)
		{	printf("Time out\n");
			break;
		}
	}
	printf("Exiting ......\n");
	return 1;
}
