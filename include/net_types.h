#ifndef NET_TYPES_H
#define NET_TYPES_H

/*
    Above are the header guards. These prevent multiple inclusions of the same header file.
    These header guards are necessary because in OS these header files can include each other and other 
    header. It may happen that these files are loaded multiple times causing redefinition errors.
    By using these guards we ensure that the contents of this file are only included once during compilation.
*/

#include <stdint.h>
/*
    This is because we need integers define bitwidth explicitly for network protocols.
    Note that  <stdlib.h> <stdio.h> <string.h> are not included here because we do not need to print anything 
    or allocate memory or use any string. Read the DESIGN PRINCIPLES README.md for more details. Also, this keeps
    kernel surface minimal and predictable for learning.
*/

typedef enum {
    NET_OK = 0,             // Operation successful.This is not arbitary.
    // Note : In C and Unix, Zero means success and non-zero means failure.    
    NET_ERR_FULL,           // Buffer queue is full
    NET_ERR_EMPTY,          // Buffer queue is empty
    NET_ERR_INVALID,        // Invalid argument or state.
    NET_ERR_PARSE,          // Packet parsing failed
    NET_ERR_UNSUPPORTED,    // Protocol or feature not supported
} net_status_t;

/*
    net_status_t:
    Represents the result of an operation within the network ingress subsystem.
    Functions return explicit status codes instead of printing errors or terminating execution.
    This follows kernel-style error handling principles.
*/

typedef enum{
    NET_PROTO_UNKNOWN = 0,
    NET_PROTO_ICMP = 1,  // Internet Control Message Protocol
    NET_PROTO_TCP  = 6,  // Transmission Control Protocol
    NET_PROTO_UDP  = 17  // User Datagram Protocol
} net_protocol_t;

/*
    net_protocol_t:
    Represents various network protocols.
    Again there numbers are not arbitarary. IPv4 specification defines them.
    These are official protocol numbers assigned by IANA.
    Read more here: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
*/

#endif