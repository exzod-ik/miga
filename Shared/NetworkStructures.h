#pragma once

#include <vector>

#pragma pack(push, 1)

 // IP-header (RFC 791)
typedef struct _IP_HEADER {
    union {
        uint8_t ver_hlen;
        struct {
            uint8_t header_len : 4;
            uint8_t version : 4;
        };
    };
    uint8_t  tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t flags_offset;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
} IP_HEADER, * PIP_HEADER;

// TCP-header (RFC 793)
typedef struct _TCP_HEADER {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    union {
        struct {
            uint16_t reserved : 4;
            uint16_t data_offset : 4;
            uint16_t flags : 8;
        };
        uint16_t word;
    };
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
} TCP_HEADER, * PTCP_HEADER;

// UDP-header (RFC 768)
typedef struct _UDP_HEADER {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
} UDP_HEADER, * PUDP_HEADER;

#pragma pack(pop)
