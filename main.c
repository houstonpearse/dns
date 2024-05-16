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
#define TCP_SIZE_HEADER 2
#define BYTE_TO_BIT 8

uint8_t *read_tcp_from_socket(int sockfd,int *sizeptr);

int main(int argc,char** argv) {
    int sockfd_out,sockfd_inc,newsockfd_inc, re, s,inc_mes_len,out_mes_len;
	uint8_t *cbuffer,*upsbuffer;
	struct addrinfo hints_inc, hints_out, *res_inc, *res_out,*rp;
	struct sockaddr_storage client_addr;
	socklen_t client_addr_size;
    dns_message_t *inc_message,*out_message;


    /* the ip and port of the server the messages will be forwarded to */
    if (argc < 3) {
		fprintf(stderr, "usage %s serverIP port\n", argv[0]);
		exit(EXIT_FAILURE);
	}

    /************** for incomming messages **************/

	/* Create address we're going to listen on with port number 8053 */
	memset(&hints_inc, 0, sizeof hints_inc);
	hints_inc.ai_family = AF_INET;
	hints_inc.ai_socktype = SOCK_STREAM;
	hints_inc.ai_flags = AI_PASSIVE;
	s = getaddrinfo(NULL, LOCAL_PORT_NUM, &hints_inc, &res_inc);

    /* check if we succeeded */
	if (s != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
		exit(EXIT_FAILURE);
	}




    /*************** for outgoing messages **************/
    
    /* get the address info of the server we are going to forward to */
    memset(&hints_out, 0, sizeof hints_out);
	hints_out.ai_family = AF_INET;
	hints_out.ai_socktype = SOCK_STREAM;
	s = getaddrinfo(argv[1], argv[2], &hints_out, &res_out);

    /* check if we suceeded */
	if (s != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
		exit(EXIT_FAILURE);
	}
    

    /*************** establish connection to server **************/
    
    /* attempt to connect to the first valid result */
    for (rp = res_out; rp != NULL; rp = rp->ai_next) {
		sockfd_out = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sockfd_out == -1)
			continue;

		if (connect(sockfd_out, rp->ai_addr, rp->ai_addrlen) != -1)
			break; // success

		close(sockfd_out);
	}


    /************* connect to new client and process   *************/
    while(true) {

        /*************** setup socket for incomming messages **************/

        /* Create new socket to listen on */
        sockfd_inc = socket(res_inc->ai_family, res_inc->ai_socktype, res_inc->ai_protocol);
        if (sockfd_inc < 0) {
            perror("socket_inc");
            exit(EXIT_FAILURE);
        }

        /* so we can reuse port */
        re = 1;
        if (setsockopt(sockfd_inc, SOL_SOCKET, SO_REUSEADDR, &re, sizeof(int)) < 0) {
            perror("setsockopt_inc");
            exit(EXIT_FAILURE);
        }

        /* bind to socket */
        if (bind(sockfd_inc, res_inc->ai_addr, res_inc->ai_addrlen) < 0) {
            perror("bind");
            exit(EXIT_FAILURE);
        }

        /* listen on socket */
        if (listen(sockfd_inc, 5) < 0) {
            perror("listen");
            exit(EXIT_FAILURE);
        }

        /* accept a connection request */
        client_addr_size = sizeof client_addr;
        newsockfd_inc =
            accept(sockfd_inc, (struct sockaddr*)&client_addr, &client_addr_size);
        if (newsockfd_inc < 0) {
            perror("accept");
            exit(EXIT_FAILURE);
        }
        
        /************ read message from a client ******************/
        
        cbuffer = read_tcp_from_socket(newsockfd_inc,&inc_mes_len);

        /* write to log */
        inc_message = new_dns_message(&cbuffer[2],inc_mes_len-2);
        write_to_log(inc_message,0);

        /*************** forward message to server ***************/

        if (write(sockfd_out, cbuffer, inc_mes_len)!=inc_mes_len) {
            printf("whole message not sent to up stream\n");
        }

        /***************** read response from server ************/

        upsbuffer = read_tcp_from_socket(sockfd_out,&out_mes_len);
        out_message = new_dns_message(&upsbuffer[2],out_mes_len-2);


        /************* forward response to client *************/

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
    int packet_len,total_len;
    /* first two bytes is for packet size */
    buffer = malloc(TCP_SIZE_HEADER*sizeof(uint8_t));
    if (read(sockfd,buffer,TCP_SIZE_HEADER)!=TCP_SIZE_HEADER) {
        printf("ERROR: failed to read TCP size header\n");
    }

    /* read rest of message from client */
    packet_len = ((buffer[0]<<BYTE_TO_BIT)|buffer[1]);
    total_len = packet_len + TCP_SIZE_HEADER;
    buffer = realloc(buffer,total_len);
    if(read(sockfd,&buffer[2],packet_len)!=packet_len) {
        printf("ERROR: failed to read whole tcp message\n");
    }

    *sizeptr = total_len;
    return buffer;
    
}

