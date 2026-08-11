
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_PACKETS 100
#define HEADER_SIZE 16

typedef struct {
    uint32_t packet_id;
    uint32_t data_size;
    uint8_t  flags;
    uint8_t  reserved[3];
} PacketHeader;

typedef struct {
    PacketHeader header;
    uint8_t      *data;
    uint32_t     checksum;
} NetworkPacket;

static NetworkPacket *packet_queue[MAX_PACKETS];
static int queue_size = 0;


int parse_packet(const uint8_t *raw_data, uint32_t raw_size) {
    if (!raw_data || raw_size < sizeof(PacketHeader)) {
        return -1;
    }

    const PacketHeader *header = (const PacketHeader *)raw_data;

    

    
    
    if (header->data_size + HEADER_SIZE > raw_size) {
        return -2;
    }

    NetworkPacket *packet = (NetworkPacket *)malloc(sizeof(NetworkPacket));

    
    memcpy(&packet->header, header, sizeof(PacketHeader));


    
    
    
    packet->data = (uint8_t *)malloc(header->data_size);
    memcpy(packet->data, raw_data + HEADER_SIZE, header->data_size);

    packet->checksum = 0;
    for (uint32_t i = 0; i < header->data_size; i++) {
        packet->checksum ^= packet->data[i];
    }

    if (queue_size < MAX_PACKETS) {
        packet_queue[queue_size++] = packet;
    } else {
        free(packet->data);
        free(packet);
        return -3;
    }

    return 0;
}


void process_packets() {
    for (int i = 0; i < queue_size; i++) {
        NetworkPacket *p = packet_queue[i];
        if (p) {
            printf("Packet #%u: size=%u, checksum=0x%08x\n",
                   p->header.packet_id, p->header.data_size, p->checksum);
        }
    }
}


void cleanup_packets() {
    for (int i = 0; i < queue_size; i++) {
        if (packet_queue[i]) {
            free(packet_queue[i]->data);
            free(packet_queue[i]);
            packet_queue[i] = NULL;
        }
    }
    queue_size = 0;
}

int main() {
    
    uint8_t malicious_packet[HEADER_SIZE] = {0};
    PacketHeader *hdr = (PacketHeader *)malicious_packet;
    hdr->packet_id = 1;
    hdr->data_size = 0xFFFFFFF1;  
    hdr->flags = 0x01;

    parse_packet(malicious_packet, sizeof(malicious_packet));

    process_packets();
    cleanup_packets();
    return 0;
}
