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

int connection(struct connection *conn) {
    struct addrinfo hints,*res,*rp;
    int s,sockfd;
    char port_string[10];
    
    /* create address we will send to */
    sprintf(port_string,"%d",conn->port);
    memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = conn->socket_type;
	s = getaddrinfo(conn->ip, port_string, &hints, &res);

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
                printf("connected to %s:%d on socket %d with type %d\n",conn->ip,conn->port,sockfd,conn->socket_type);
                conn->socket = sockfd;
                return sockfd;
            }
            perror("connect");
            close(sockfd);
        }
	}
    return -1;
}

int reconnect(struct connection *conn) {
    close(conn->socket);
    return connection(conn);
}

uint8_t *send_request(struct connection *conn, uint8_t *buffer, int buffer_len, int *response_len, int retry) {
    uint8_t *response = NULL;
    int bytes_written=0,attempts=0,retries=0;
    if (conn->socket_type==SOCK_STREAM) { // tcp
        do {
            attempts=0;
            do {
                printf("(%d) Sending request\n",conn->socket);
                bytes_written = write_buffer(conn->socket,buffer,buffer_len);
                if (bytes_written==buffer_len) break;
                if (attempts>=retry) {
                    printf("(%d) Failed to send request\n",conn->socket);
                    return NULL;
                }
                printf("(%d) Failed to send request. Closing connection and Retrying.\n",conn->socket);
                if (reconnect(conn)<0) {
                    printf("(%d) Failed to reconnect\n",conn->socket); 
                    return NULL;
                }
                attempts++;
            } while(attempts<retry);
            
            printf("(%d) Reading response\n",conn->socket);
            response = read_tcp(conn->socket,response_len); 
            if (response != NULL){
                break;
            };
            if (retries+1>=retry) {
                printf("(%d) Failed to read a response.\n",conn->socket);
            } else {
                printf("(%d) Failed to read response. Closing connection and Retrying.\n",conn->socket);
            }
            if (reconnect(conn)<0) {
                printf("(%d) Failed to reconnect\n",conn->socket); 
                return NULL;
            }

            retries++;
        } while (retries<retry);

        return response;
    } else if (conn->socket_type==SOCK_DGRAM) {
        // udp connection
        return NULL;
    } else {
        fprintf(stderr,"Invalid connection type (%d) expected 1 for TCP and 2 for UDP\n",conn->socket_type);
        return NULL;
    }

}
