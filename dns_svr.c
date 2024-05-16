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

#define LOG_FILE_PATH "dns_svr.log"
#define LOCAL_PORT_NUM "8053"
#define LISTEN_QUEUE_NUM 20
#define TCP_SIZE_HEADER 2
#define BYTE_TO_BIT 8
#define NOT_REPLY 0
#define REPLY 1

uint8_t *read_tcp_from_socket(int sockfd,int *sizeptr);
void write_tcp_to_socket(int sockfd, uint8_t *buffer,int buffer_size);
int setup_forwarding_socket(char ip[],char port[]);
int setup_listening_socket();
void handle_new_connection(int newsockfd_inc,int sockfd_out, int *first);
void write_log_message(char *message,int *first);


int main(int argc,char** argv) {
    int sockfd_out,sockfd_inc,newsockfd_inc,first=1;
	struct sockaddr_storage client_addr;
	socklen_t client_addr_size;


    /* the ip and port of the server the messages will be forwarded to */
    if (argc < 3) {
		fprintf(stderr, "usage %s serverIP port\n", argv[0]);
		exit(EXIT_FAILURE);
	}
    FILE *fp = fopen(LOG_FILE_PATH,"a");
    fclose(fp);


    /* sets up socket to receive incomming connections and listens */
    sockfd_inc = setup_listening_socket();

    
    while(true) {
        printf("\n\n-------------------------------------------------\n");
        printf("waiting for new connections...\n");
        /* accept a connection request on our listening socket */
        client_addr_size = sizeof client_addr;
        newsockfd_inc = 
        accept(sockfd_inc, (struct sockaddr*)&client_addr, &client_addr_size);
        
        
        /* check if we succeeded */
        if (newsockfd_inc < 0) {
            perror("accept");
            exit(EXIT_FAILURE);
        }
        
        printf("accepted a new connection. socketfd = %d\n",newsockfd_inc);
        printf("setup upstream connection...\n");

        sockfd_out = setup_forwarding_socket(argv[1], argv[2]);

        
        printf("handling new connection...\n");
        handle_new_connection(newsockfd_inc,sockfd_out,&first);

        close(sockfd_out);
        
    }

    close(sockfd_inc);
    
    
    
}

/**************** helpers *****************/

/* handles new connections */
void handle_new_connection(int newsockfd_inc,int sockfd_out,int *first) {
    int inc_mes_len,out_mes_len;
    uint8_t *cbuffer,*upsbuffer;
    dns_message_t *out_message,*inc_message;
    char *logstring;

    printf("reading from client...\n");
    /* read from client. will store message len in inc_mes_len */
    cbuffer = read_tcp_from_socket(newsockfd_inc,&inc_mes_len);

    
    /* write to log */
    printf("creating dns struct...\n");
    inc_message = new_dns_message(&cbuffer[2],inc_mes_len-2);
    printf("writing to log...\n");
    logstring = get_log_message(inc_message);
    if (logstring!=NULL) {
        printf("--log--\n");
        printf("%s\n",logstring);
        printf("--log--\n");
        write_log_message(logstring,first);
    }
    print_message(inc_message);

    /* if we have received a non AAAA query */
    if(inc_message->question.is_AAAA == false) {
        
        printf("request was for IPv4, set rcode and parameters...\n");
        // set Rcode in query to 4
        set_parameters(&cbuffer[2],inc_mes_len-2);
        
        printf("creating the altered dns struct...\n");
        out_message = new_dns_message(&cbuffer[2],inc_mes_len-2);
        print_message(out_message);

        printf("send altered packet back...\n");
        // write back to client
        write_tcp_to_socket(newsockfd_inc,cbuffer,inc_mes_len);

        printf("closing connection...\n");
        close(newsockfd_inc);
        free_dns_message(inc_message);
        free_dns_message(out_message);
        free(cbuffer);
        return;
        
    }
    
    printf("forwarding to server...\n");
    /* forward message to server */
    write_tcp_to_socket(sockfd_out,cbuffer,inc_mes_len);
    
    printf("reading from server...\n");
    /* get response from server */
    upsbuffer = read_tcp_from_socket(sockfd_out,&out_mes_len);
    out_message = new_dns_message(&upsbuffer[2],out_mes_len-2);
    logstring = get_log_message(out_message);
    if (logstring!=NULL) {
        printf("--log--\n");
        printf("%s\n",logstring);
        printf("--log--\n");
        write_log_message(logstring,first);
    }
    print_message(out_message);
    

    printf("forwarding to client...\n");
    /* forward server response to client */
    write_tcp_to_socket(newsockfd_inc,upsbuffer,out_mes_len);
    
    printf("closing connection...\n");
    close(newsockfd_inc);

    free_dns_message(out_message);
    free_dns_message(inc_message);
    free(cbuffer);
    free(upsbuffer);

}

/* reads a response packet from a socket, stores size in pointer */
uint8_t *read_tcp_from_socket(int sockfd,int *sizeptr) {
    uint8_t *buffer;
    int current_len=0,bytes_to_read=0,bytes_read=0;

    printf("allocating memory header...\n");
    // allocate memory for two byte tcp size header
    buffer = malloc(TCP_SIZE_HEADER*sizeof(uint8_t));

    // read two byte size header
    printf("reading size header...\n");
    current_len += read(sockfd,buffer,TCP_SIZE_HEADER);

    // get number of bytes of the remaining message
    //bytes_to_read = buffer[0]<<8 | buffer[1];
    bytes_to_read = ntohs(*(uint16_t*)buffer);
    //bytes_to_read = *(uint16_t*)buffer;
    //*(uint16_t*)buffer = htons(*(uint16_t*)buffer);
    printf("size is %d, reallocate...\n",bytes_to_read);
    buffer = realloc(buffer,(bytes_to_read+TCP_SIZE_HEADER)*sizeof(uint8_t));


    // read rest of message
    while (true) {
        bytes_read=read(sockfd,&buffer[current_len],bytes_to_read);
        bytes_to_read-=bytes_read;
        current_len+=bytes_read;
        if (bytes_to_read == 0) {
            break;
        }
    }

    printf("got message...\n");
    *sizeptr = current_len;
    hex_dump(buffer,current_len);
    return buffer;

}

/* writes a buffer to a socket. will keep trying to send untill entire buffer
 *is received
*/
void write_tcp_to_socket(int sockfd, uint8_t *buffer,int buffer_size) {
    int bytes_written,bytes_sent,bytes_rem;
    
    bytes_rem = buffer_size;
    bytes_sent = 0;
    while(true) {
        bytes_written=write(sockfd,&buffer[bytes_sent],bytes_rem);
        bytes_rem-=bytes_written;
        bytes_sent+=bytes_written;
        if(bytes_rem==0) {
            printf("wrote %d bytes. bufferlen is %d\n",bytes_sent,buffer_size);
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

void write_log_message(char *message,int *first) {
    if (message==NULL) return;
    FILE *fp = fopen(LOG_FILE_PATH,"a");
    if(*first) {
        fprintf(fp,"%s",message);
    }
    fprintf(fp,"%s\n",message);
    fflush(fp);
    fclose(fp);
}
