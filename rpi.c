#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <byteswap.h>

struct IPHeader {
	uint8_t version;
	uint8_t ihl;
	uint8_t tos;
	uint16_t total_length;
	uint16_t id;
	uint8_t flags;
	uint16_t fragment_offset;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t checksum;
	uint32_t source_address;
	uint32_t dest_address;
	uint32_t options;
};

struct TCPHeader {
	uint16_t source_port;
	uint16_t dest_port;
	uint32_t seq_number;
	uint32_t ack_number;
	int data_offset;
	uint8_t flags;
	uint8_t urgent_pointer;
	uint32_t options;
};

void printAddress(uint32_t addr) {
	uint8_t* ptr = (uint8_t*)&addr;
	printf("%u.", ptr[3]);
	printf("%u.", ptr[2]);
	printf("%u.", ptr[1]);
	printf("%u", ptr[0]);
}

char* TOStoString(uint8_t tos) {
	char *base = malloc(1000); // Lazy!
	memset(base, 0, 1000);

	strcat(base, "Precedence(");

	uint8_t prec = (tos & 0xE0) >> 5;
	switch(prec) {
	case 0: strcat(base, "Routine"); break;
	case 1: strcat(base, "Priority"); break;
	case 2: strcat(base, "Immediate"); break;
	case 3: strcat(base, "Flash"); break;
	case 4: strcat(base, "Flash Override"); break;
	case 5: strcat(base, "CRITIC/ECP"); break;
	case 6: strcat(base, "Internetwork Control"); break;
	case 7: strcat(base, "Network Control"); break;
	}
	strcat(base, ")");

	if (tos & 0x3) {
		strcat(base, "|Low Delay");
	} else {
		strcat(base, "|Normal Delay");
	}

	if (tos & 0x4) {
		strcat(base, "|High Throughput");
	} else {
		strcat(base, "|Normal Throughput");
	}

	if (tos & 0x5) {
		strcat(base, "|High Reliability");
	} else {
		strcat(base, "|Normal Reliability");
	}

	return base;
}

char* FlagstoString(uint8_t flags) {
	char *base = malloc(100); // Lazy!
	memset(base, 0, 100);

	if (flags & 0x1) {
		strcat(base, "May Fragment");
	} else {
		strcat(base, "Don't Fragment");
	}

	if (flags & 0x2) {
		strcat(base, "|Last Fragment");
	} else {
		strcat(base, "|More Fragments");
	}

	return base;
}

void printIPPacketHeader(struct IPHeader *header) {
	printf("IP Header:\n");
	printf("\tVersion: %u\n", header->version);
	printf("\tIHL: %u (32bit words)\n", header->ihl);
	printf("\tTOS: %s\n", TOStoString(header->tos));
	printf("\tTotal Length: %zd\n", header->total_length);
	printf("\tIdentification: %zd\n", header->id);
	printf("\tFlags: %s\n", FlagstoString(header->flags));
	printf("\tFragment Offset: %d\n", header->fragment_offset);
	printf("\tTTL: %u\n", header->ttl);
	printf("\tProtocol: %u\n", header->protocol);
	printf("\tChecksum: %zd\n", header->checksum);
	printf("\tSource Address: "); printAddress(header->source_address); printf("\n");
	printf("\tDestination Address: "); printAddress(header->dest_address); printf("\n");
}

struct IPHeader* getIPPacketHeader(void *buffer, unsigned int plen) {
	struct IPHeader *header;

	header = malloc(sizeof(struct IPHeader));
	if (header == NULL) {
		printf("Null IPHeader Allocation: %s\n", strerror(errno));
		exit(1);
	}

	header->version = ((((uint8_t*)buffer)[0]) >> 4);
	header->ihl = (((uint8_t*)buffer)[0]) & 0xF;
	header->tos = (((uint8_t*)buffer)[1]);
	header->total_length = be16toh(((uint16_t*)buffer)[1]);
	header->id = be16toh((((uint16_t*)buffer)[2]));
	header->fragment_offset = be16toh((((uint16_t*)buffer)[3]) & 0x1fff);
	header->flags = ((((uint16_t*)buffer)[3]) >> 13) & 0x7;
	header->ttl = ((uint8_t*)buffer)[8];
	header->protocol = ((uint8_t*)buffer)[9];
	header->checksum = ((uint16_t*)buffer)[5];
	header->source_address = be32toh(((uint32_t*)buffer)[3]);
	header->dest_address = be32toh(((uint32_t*)buffer)[4]);
	header->options = be32toh((((uint32_t*)buffer)[5]) >> 8);

	return header;
}

void printTCPPacketHeader(struct TCPHeader *header) {
  printf("TCP Header:\n");
  printf("\tSource Port: \t\t%d\n", be16toh(header->source_port));
  printf("\tDestination Port: \t%d\n", be16toh(header->dest_port));
}

struct TCPHeader* getTCPPacketHeader(void *buffer, unsigned int plen) {
  struct TCPHeader *header;

  header = malloc(sizeof(struct TCPHeader));
  if(header == NULL) {
    printf("Failed to allocate header: %s\n", strerror(errno));
    exit(1);
  }

  header->source_port = ((uint16_t*)buffer)[0];
  header->dest_port = ((uint16_t*)buffer)[1];
  header->seq_number = ((uint32_t*)buffer)[1];
  header->ack_number = ((uint32_t*)buffer)[2];

  return header;
}

int main(void) {
  int i, recv_length, sockfd;

  FILE *fn = fopen("header.bin", "w");
  if (fn == NULL) {
    printf("Error opening header dump (header.bin)\n");
    exit(1);
  }
  
  if ((sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
    printf("Socket failed: %s\n", strerror(errno));
    exit(1);
  }

  char buffer[1024*10];
  memset(buffer, 0, sizeof(buffer));

  struct sockaddr serv_addr;
  memset(&serv_addr, 0, sizeof(serv_addr));

  printf("Receiving....\n");
  unsigned int fromlen = sizeof(serv_addr);
  ssize_t nrecv = recvfrom(sockfd, buffer, sizeof(buffer), 0,
			   &serv_addr, &fromlen);
  if (nrecv < 0) {
    printf("recv error: %s\n", strerror(errno));
    exit(1);
  } else {
    printf("Wrote %zd bytes\n", nrecv);
  }

  struct IPHeader* header = getIPPacketHeader(buffer, nrecv);
  printIPPacketHeader(header);
  
  int ret = fwrite(buffer, nrecv, 1, fn);
  if (ret < 0) {
    printf("Failed to write: %s\n", strerror(errno));
    exit(1);
  }
    
  ret = fflush(fn);
  if (ret == -1) {
    printf("Failed to flush: %s\n", strerror(errno));
    exit(1);
  }
  
  fclose(fn);
  shutdown(0, sockfd);
  return 0;
}
