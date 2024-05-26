#include <poll.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>
#include <ctype.h>
#include "connection.h"

/* reads a response packet from a socket, stores size in pointer */
uint8_t *read_tcp(int sockfd,int *sizeptr) {
    uint8_t *buffer;
    int packet_size;

    // read 2 byte size header 
    buffer = malloc(TCP_SIZE_HEADER_LENGTH*sizeof(uint8_t));
    if ((*sizeptr = read_buffer(sockfd,buffer,0,TCP_SIZE_HEADER_LENGTH))==-1) {
        free(buffer);
        return NULL;
    }

    // read number of remaining bytes
    packet_size = ntohs(*(uint16_t*)buffer) + *sizeptr;
    buffer = realloc(buffer,packet_size*sizeof(uint8_t));

    // read rest of message
    if ((*sizeptr = read_buffer(sockfd,buffer,*sizeptr,packet_size))==-1) {
        free(buffer);
        return NULL;
    }
    return buffer;
}


int read_buffer(int sockfd, uint8_t *buffer,int buffer_pos, int buffer_size) {
    int bytes_read,read_pos=buffer_pos;
    while (read_pos<buffer_size) {
        bytes_read=read(sockfd,&buffer[read_pos],buffer_size-read_pos);
        if (bytes_read < 0) {
            perror("read buffer");
            int err = errno;
            if ((err == EAGAIN) || (err == EWOULDBLOCK)){
                // retry after polling period
                struct pollfd pfds = {0};
                pfds.events = POLL_IN;
                pfds.fd = sockfd;
                if (poll(&pfds,1,-1)==-1) {
                    perror("poll");
                    exit(1);
                } else if (pfds.revents & POLL_IN) {
                    // can now retry
                    continue;
                } else {
                    return -1;
                };
            } else if (errno == EINTR) {
                // safe to retry
                continue;
            } else {
                // fatal error
                return -1;
            }
        } else {
            read_pos+=bytes_read;
        }
    }
    return read_pos;
}

/* Writes a entire buffer and retries if entire buffer it not written */
int write_buffer(int sockfd, uint8_t *buffer,int buffer_size) {
    int bytes_written=0,bytes_sent=0;
    while(bytes_sent<buffer_size) {
        bytes_written=write(sockfd,&buffer[bytes_sent],buffer_size-bytes_sent);
        if (bytes_written < 0) {
            perror("write buffer");
            int err = errno;
            if ((err == EAGAIN) || (err == EWOULDBLOCK)){
                // retry after polling period
                struct pollfd pfds = {0};
                pfds.events = POLL_OUT;
                pfds.fd = sockfd;
                if (poll(&pfds,1,-1)==-1) {
                    perror("poll");
                    exit(1);
                } else if (pfds.revents & POLL_OUT) {
                    // can now retry
                    continue;
                } else {
                    return -1;
                };
            } else if (errno == EINTR) {
                // safe to retry
                continue;
            } else {
                // fatal error
                return -1;
            }
        } else {
            bytes_sent+=bytes_written;
        }
    }
    return bytes_sent;
}

/* Sets up a listening socket
    @param char *port - The port to listen on
    @param int queue_size - The maximum number of connections in the queue
*/
int listening_socket(int port, int queue_size) {
    struct addrinfo hints,*res;
    int opt=1,s,sockfd;
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
    if ((sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0) {
        perror("socket_inc");
        exit(EXIT_FAILURE);
    }

    /* so we can reuse port */
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
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

int connection(char ip[],int port,int socket_type) {
    struct addrinfo hints,*res,*rp;
    int s,sockfd;
    char port_string[10];

    /* create address we will send to */
    sprintf(port_string,"%d",port);
    memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = socket_type;
	s = getaddrinfo(ip, port_string, &hints, &res);

    /* check if we suceeded */
	if (s != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
		return -1;
	}
    
    /* attempt to connect to the first valid result */
    for (rp = res; rp != NULL; rp = rp->ai_next) {
		sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sockfd != -1) {
            if (connect(sockfd, rp->ai_addr, rp->ai_addrlen) != -1) {
                return sockfd;
            }
            close(sockfd);
        }
	}
    return -1;
}
