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

int main(int argc,char** argv) {
    int sockfd_out,sockfd_inc,newsockfd_inc, re, s,len;
	uint8_t *cbuffer,*upsbuffer;
	struct addrinfo hints_inc, hints_out, *res_inc, *res_out,*rp;
	struct sockaddr_storage client_addr;
	socklen_t client_addr_size;
    dns_message_t *message;


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
        
        /* first two bytes is for packet size */
        cbuffer = malloc(2*sizeof(uint8_t));
        if (read(newsockfd_inc,cbuffer,2)!=2) {
            printf("failed to read size from client query\n");
        }

        /* read rest of message from client */
        len = ((cbuffer[0]<<8)|cbuffer[1]);
        cbuffer = realloc(cbuffer,len+2);
        if(read(newsockfd_inc,&cbuffer[2],len)!=len) {
            printf("whole message not read from client\n");
        }

        message = new_dns_message(&cbuffer[2],len);
        write_to_log(message);

        /*************** forward message to server ***************/

        if (write(sockfd_out, cbuffer, len+2)!=len+2) {
            printf("whole message not sent to up stream\n");
        }

        /***************** read response from server ************/

        /* get size of responce from first two bytes */
        upsbuffer = malloc(2*sizeof(uint8_t));
        if(read(sockfd_out,upsbuffer,2)!=2) {
            printf("failed to read size from upstream response\n");
        }

        len = ((upsbuffer[0]<<8)|upsbuffer[1]);
        upsbuffer = realloc(upsbuffer,len+2);
        if(read(sockfd_out,&upsbuffer[2],len)!=len) {
            printf("whole message not received by server from upsteam\n");
        }

        //message = new_dns_message(&upsbuffer[2],len);
        //print_message(message);
        //print_log(message);

        /************* forward response to client *************/

        if(write(newsockfd_inc,upsbuffer,len+2)!=len+2) {
            printf("whole message not received by client\n");
        }


        close(newsockfd_inc);
    }

    close(sockfd_inc);
    close(sockfd_out);
    
    
}
