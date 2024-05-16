// a dns server using TCP 
// by Houston Pearse 994653
// code adapted from week9 materials

#define _POSIX_C_SOURCE 200112L
#include <ctype.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define LOCAL_PORT_NUM 8053

int main(int argc,char** argv) {
    int sockfd, newsockfd, n, re, i, s;
	char buffer[256];
	struct addrinfo hints_inc, hints_out, *res_inc, *res_out,*rp;
	struct sockaddr_storage client_addr;
	socklen_t client_addr_size;


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
		sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sockfd == -1)
			continue;

		if (connect(sockfd, rp->ai_addr, rp->ai_addrlen) != -1)
			break; // success

		close(sockfd);
	}

    /*************** accept incomming messages **************/

    /* Create new socket to listen on */
	sockfd = socket(res_inc->ai_family, res_inc->ai_socktype, res_inc->ai_protocol);
	if (sockfd < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

    /* so we can reuse port */
	re = 1;
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &re, sizeof(int)) < 0) {
		perror("setsockopt");
		exit(EXIT_FAILURE);
	}

    /* bind to socket */
    if (bind(sockfd, res_inc->ai_addr, res_inc->ai_addrlen) < 0) {
		perror("bind");
		exit(EXIT_FAILURE);
	}



    
}
