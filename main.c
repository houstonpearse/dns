// a dns server using TCP 
// by Houston Pearse 994653
// code adapted from week9 materials

#include "dns_message.h"

#include <ctype.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define LOCAL_PORT_NUM "8053"
#define LISTEN_QUEUE_NUM 20
#define TCP_SIZE_HEADER 2
#define BYTE_TO_BIT 8

uint8_t *read_tcp_from_socket(int sockfd,int *sizeptr);
void write_tcp_to_socket(int sockfd, uint8_t *buffer,int buffer_size);

int setup_forwarding_socket(char ip[],char port[]);
int setup_listening_socket();


int main(int argc,char** argv) {
    int sockfd_out,sockfd_inc,newsockfd_inc,inc_mes_len,out_mes_len;
	uint8_t *cbuffer,*upsbuffer;
	struct sockaddr_storage client_addr;
	socklen_t client_addr_size = sizeof client_addr;
    dns_message_t *inc_message,*out_message;


    /* the ip and port of the server the messages will be forwarded to */
    if (argc < 3) {
		fprintf(stderr, "usage %s serverIP port\n", argv[0]);
		exit(EXIT_FAILURE);
	}

    /* sets up socket we will be forwarding our requests to */
	sockfd_out = setup_forwarding_socket(argv[1], argv[2]);

    /* sets up socket to receive incomming connections and listens */
    sockfd_inc = setup_listening_socket();

    
    while(true) {
        
        /* accept a connection request on our listening socket */
        newsockfd_inc = 
        accept(sockfd_inc, (struct sockaddr*)&client_addr, &client_addr_size);
        
        /* check if we succeeded */
        if (newsockfd_inc < 0) {
            perror("accept");
            exit(EXIT_FAILURE);
        }
        
        /* read from client. will store message len in inc_mes_len */
        cbuffer = read_tcp_from_socket(newsockfd_inc,&inc_mes_len);

        /* write to log */
        inc_message = new_dns_message(&cbuffer[2],inc_mes_len-2);
        write_to_log(inc_message,0);

        /* forward message to server */
        write_tcp_to_socket(sockfd_out,cbuffer,inc_mes_len);
        

        /* get response from server */
        upsbuffer = read_tcp_from_socket(sockfd_out,&out_mes_len);
        out_message = new_dns_message(&upsbuffer[2],out_mes_len-2);


        /* forward response to client */

        /* check if request was ipv6 */
        if(inc_message->question.is_AAAA == false) {
            // change inc_message to have Rcode 4
            set_rcode(&cbuffer[2],inc_mes_len-2,4);
            // send original message back with Rcode 4
            if(write(newsockfd_inc,cbuffer,inc_mes_len)!=inc_mes_len) {
                printf("whole message not received by client\n");
            }
        } else {
            // send message received from upstream
            if(write(newsockfd_inc,upsbuffer,out_mes_len)!=out_mes_len) {
                printf("whole message not received by client\n");
            }
            /* write to log */
            write_to_log(new_dns_message(&upsbuffer[2],out_mes_len-2),1);
        }

        
        close(newsockfd_inc);
    }

    close(sockfd_inc);
    close(sockfd_out);
    
    
}

/**************** helpers *****************/

/* reads a response packet from a socket, stores size in pointer */
uint8_t *read_tcp_from_socket(int sockfd,int *sizeptr) {
    uint8_t *buffer;
    int packet_len,total_len,current_len,bytes_to_read,bytes_read;

    buffer = malloc(TCP_SIZE_HEADER*sizeof(uint8_t));
    current_len = 0;
    while (true) {
        /* we have yet to read the two byte tcp size header */
        if (current_len<TCP_SIZE_HEADER) {
            current_len+=
            read(sockfd,&buffer[0+current_len],TCP_SIZE_HEADER-current_len);
            /* check if we can get the size from the first two bytes */
            if (current_len == TCP_SIZE_HEADER) {
                packet_len = ((buffer[0]<<BYTE_TO_BIT)|buffer[1]);
                total_len = packet_len + TCP_SIZE_HEADER;
                buffer = realloc(buffer,total_len);
                bytes_to_read = packet_len;
            }
        }

        /* if we have read the header, start reading rest of message */
        if(current_len>=TCP_SIZE_HEADER) {
            bytes_read=read(sockfd,&buffer[0+current_len],bytes_to_read);
            bytes_to_read-=bytes_read;
            current_len+=bytes_read;
            if (bytes_to_read == 0) {
                *sizeptr = total_len;
                return buffer;
            }
        }
    }
}

/* writes a buffer to a socket. will keep trying to send untill entire buffer
 *is received
*/
void write_tcp_to_socket(int sockfd, uint8_t *buffer,int buffer_size) {
    int bytes_sent=0,bytes_rem = buffer_size,bytes_written;
    while(true) {
        bytes_written=write(sockfd,&buffer[0+bytes_sent],bytes_rem);
        bytes_rem-=bytes_written;
        bytes_sent+=bytes_written;
        if(bytes_rem==0) {
            return;
        }
    }
}

/* sets up listening socket */
int setup_listening_socket() {
    struct addrinfo hints,*res;
    int re,s,sockfd;

    /* Create address we're going to listen on with port number 8053 */
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	s = getaddrinfo(NULL, LOCAL_PORT_NUM, &hints, &res);

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
    if (listen(sockfd, LISTEN_QUEUE_NUM) < 0) {
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

