#include "connection.h"

/* reads a response packet from a socket, stores size in pointer */
uint8_t *read_tcp(int sockfd,int *sizeptr) {
    uint8_t *buffer;
    int packet_size,bytes_read;

    // read 2 byte size header 
    buffer = malloc(TCP_SIZE_HEADER_LENGTH*sizeof(uint8_t));
    *sizeptr=0;
    while (*sizeptr<TCP_SIZE_HEADER_LENGTH) {
        bytes_read=read(sockfd,&buffer[*sizeptr],TCP_SIZE_HEADER_LENGTH-*sizeptr);
        if (bytes_read < 0) {
            perror("read tcp");
            free(buffer);
            return NULL;
        }
        *sizeptr+=bytes_read;
    }

    // read number of remaining bytes
    packet_size = ntohs(*(uint16_t*)buffer) + *sizeptr;
    buffer = realloc(buffer,packet_size*sizeof(uint8_t));

    // read rest of message
    while (*sizeptr<packet_size) {
        bytes_read=read(sockfd,&buffer[*sizeptr],packet_size-*sizeptr);
        if (bytes_read < 0) {
            perror("read tcp");
            free(buffer);
            return NULL;
        }
        *sizeptr+=bytes_read;
    }
    return buffer;
}

/* Writes a entire buffer and retries if entire buffer it not written */
int write_buffer(int sockfd, uint8_t *buffer,int buffer_size) {
    int bytes_written=0,bytes_sent=0;
    while(bytes_sent<buffer_size) {
        bytes_written=write(sockfd,&buffer[bytes_sent],buffer_size-bytes_sent);
        if (bytes_written < 0) {
            perror("write buffer");
            return -1;
        }
        printf("bytes writte %d\n",bytes_written);
        bytes_sent+=bytes_written;
    }
    return bytes_sent;
}

/* Sets up a listening socket
    @param char *port - The port to listen on
    @param int queue_size - The maximum number of connections in the queue
*/
int setup_listening_socket(int port, int queue_size) {
    struct addrinfo hints,*res;
    int re,s,sockfd;
    char port_string[10];

    /* Create address we're going to listen on with port number 8053 */
    sprintf(port_string,"%d",port);
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	s = getaddrinfo(NULL, port_string, &hints, &res);

    /* check if we succeeded */
	if (s != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
		exit(EXIT_FAILURE);
	}

    /* create socket we will listen on */
    sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sockfd < 0) {
        perror("socket_inc");
        exit(EXIT_FAILURE);
    }

    /* so we can reuse port */
    re = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &re, sizeof(int)) < 0) {
        perror("setsockopt_inc");
        exit(EXIT_FAILURE);
    }

    /* bind to socket */
    if (bind(sockfd, res->ai_addr, res->ai_addrlen) < 0) {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    /* listen on socket */
    if (listen(sockfd, queue_size) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    return sockfd;
}


int setup_forwarding_socket(char ip[],char port[]) {
    struct addrinfo hints,*res,*rp;
    int s,sockfd;

    /* create address we will send to */
    memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	s = getaddrinfo(ip, port, &hints, &res);

    /* check if we suceeded */
	if (s != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
		exit(EXIT_FAILURE);
	}
    
    /* attempt to connect to the first valid result */
    for (rp = res; rp != NULL; rp = rp->ai_next) {
		sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sockfd == -1)
			continue;

		if (connect(sockfd, rp->ai_addr, rp->ai_addrlen) != -1)
			break; // success

		close(sockfd);
	}

    return sockfd;

}
