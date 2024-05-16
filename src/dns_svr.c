#include "dns_message.h"
#include "dns_cache.h"
#include <ctype.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#define LOG_FILE_PATH "dns_svr.log"
#define LOCAL_PORT_NUM "8053"
#define LISTEN_QUEUE_NUM 20
#define TCP_SIZE_HEADER 2
#define BYTE_TO_BIT 8
#define NOT_REPLY 0
#define REPLY 1
#define CACHE
#define NONBLOCKING

uint8_t *read_tcp_from_socket(int sockfd,int *sizeptr);
void write_tcp_to_socket(int sockfd, uint8_t *buffer,int buffer_size);
int setup_forwarding_socket(char ip[],char port[]);
int setup_listening_socket(void);
void *handle_new_connection(void *args);
void write_log_message(char *message);
struct arguments {
    cache_t *cache;
    int newsockfd_inc;
    int sockfd_out;
};

pthread_mutex_t cachelock;
pthread_mutex_t connectionlock;
pthread_mutex_t filelock;

int main(int argc,char** argv) {
    int sockfd_out,sockfd_inc,newsockfd_inc;
	struct sockaddr_storage client_addr;
	socklen_t client_addr_size;
    cache_t *cache;
    struct arguments *args;

    /* the ip and port of the server the messages will be forwarded to */
    if (argc < 3) {
		fprintf(stderr, "usage %s serverIP port\n", argv[0]);
		exit(EXIT_FAILURE);
	}
    FILE *fp = fopen(LOG_FILE_PATH,"a");
    fclose(fp);

    /* sets up socket to receive incomming connections and listens */
    sockfd_inc = setup_listening_socket();

    /* setup cache */
    cache = malloc(sizeof(*cache));
    cache->lastupdate = time(NULL);

    args= malloc(sizeof(*args));
    args->cache = cache;
    printf("-------------------------------IPV6-DNS-------------------------------\n");
    printf("setup upstream connection...\n");
    sockfd_out = setup_forwarding_socket(argv[1], argv[2]);
    printf("upstream connection initiated\n");
    while(true) {
        printf("waiting for new connections...\n");
        /* accept a connection request on our listening socket */
        client_addr_size = sizeof client_addr;
        newsockfd_inc = accept(sockfd_inc, (struct sockaddr*)&client_addr, &client_addr_size);
        
        /* check if we succeeded */
        if (newsockfd_inc < 0) {
            perror("accept");
            exit(EXIT_FAILURE);
        }
        
        printf("accepted a new connection. socketfd = %d\n",newsockfd_inc);
        args = malloc(sizeof(*args));
        args->cache = cache;
        args->newsockfd_inc = newsockfd_inc;
        args->sockfd_out = sockfd_out;
        pthread_t t;
        pthread_create(&t,NULL,handle_new_connection,args);
        
    }

    close(sockfd_inc);
    
    
    
}

/**************** helpers *****************/

/* handles new connections */
void *handle_new_connection(void *args) {
    // unpack args from struct and free struct
    cache_t *cache = ((struct arguments*)args)->cache;
    int newsockfd_inc = ((struct arguments*)args)->newsockfd_inc;
    int sockfd_out = ((struct arguments*)args)->sockfd_out;
    free(args);

    int i,inc_mes_len,out_mes_len;
    uint8_t *cbuffer,*upsbuffer;
    dns_message_t *out_message,*inc_message;
    cache_item_t *cache_search_val,*new_cache_val,*evicted;
    char *logstring,*cachestring;

    printf("(%d) reading from client...\n",newsockfd_inc);
    cbuffer = read_tcp_from_socket(newsockfd_inc,&inc_mes_len);
    inc_message = new_dns_message(&cbuffer[2],inc_mes_len-2);
    if (inc_message == NULL) {
        printf("(%d) Invalid DNS Query\n",newsockfd_inc);
        pthread_mutex_unlock(&cachelock);
        close(newsockfd_inc);
        return NULL;
    } 

    printf("(%d) received client request\n",newsockfd_inc);
    logstring = get_log_message(inc_message);
    write_log_message(logstring);
    
    if(inc_message->question.is_AAAA == false) {
        printf("(%d) IPV4 Request Not Implemented.\n",newsockfd_inc);
        set_packet_headers(&cbuffer[2],inc_mes_len-2,-1,1,4,1);
        write_tcp_to_socket(newsockfd_inc,cbuffer,inc_mes_len);
        close(newsockfd_inc);
        return NULL;
    } 

    pthread_mutex_lock(&cachelock);
    cache_search_val = find_cache_item(cache,inc_message->question.domn);
    if (cache_search_val != NULL && cache_search_val->ttl>0) {
        printf("(%d) Cache hit for %s\n",newsockfd_inc,inc_message->question.domn);
        
        // copy buffer from cache
        upsbuffer = malloc(cache_search_val->buffer_size*sizeof(*upsbuffer));
        out_mes_len = cache_search_val->buffer_size;
        for (i=0;i<out_mes_len;i++) {
            upsbuffer[i]=cache_search_val->buffer[i];
        }
    
        // edit ttl and id bytes in the cached copy
        set_packet_headers(&upsbuffer[2],out_mes_len-2,inc_message->header.id,-1,-1,-1);
        set_answer_ttl(&upsbuffer[2],out_mes_len-2,cache_search_val->ttl);

        // log event
        cachestring = usage_cache_message(cache_search_val);
        write_log_message(cachestring);
        write_log_message(get_log_message(new_dns_message(&upsbuffer[2],out_mes_len-2)));
        
        // send back response
        write_tcp_to_socket(newsockfd_inc,upsbuffer,out_mes_len);
        close(newsockfd_inc);
        pthread_mutex_unlock(&cachelock);
        return NULL;
    }
    pthread_mutex_unlock(&cachelock);
    
    /* forward AAAA query to upstream server */
    printf("(%d) forwarding to upstream server...\n",newsockfd_inc);
    pthread_mutex_lock(&connectionlock);
    write_tcp_to_socket(sockfd_out,cbuffer,inc_mes_len);
    printf("(%d) reading response from upstream server...\n",newsockfd_inc);
    upsbuffer = read_tcp_from_socket(sockfd_out,&out_mes_len);
    pthread_mutex_unlock(&connectionlock);
    if (upsbuffer == NULL) {
        printf("(%d) failed to read from upstream server",newsockfd_inc);
        set_packet_headers(&cbuffer[2],inc_mes_len-2,-1,1,2,-1);
        write_tcp_to_socket(newsockfd_inc,cbuffer,inc_mes_len);
        close(newsockfd_inc);
        return NULL;
    }
    
    /* read upstream response */
    out_message = new_dns_message(&upsbuffer[2],out_mes_len-2);
    if (out_message == NULL) {
        printf("(%d) Received an unknown response from upstream server\n",newsockfd_inc);
        set_packet_headers(&cbuffer[2],inc_mes_len-2,-1,1,2,-1);
        upsbuffer=cbuffer;
        out_mes_len=inc_mes_len;
        close(newsockfd_inc);
        return NULL;
    }

    /* add to cache if we have an answer */
    if (out_message->nr>0) {
        new_cache_val = new_cache_item(out_message->question.domn,
            out_message->response.ttl,
            upsbuffer,
            out_mes_len
        );
        pthread_mutex_lock(&cachelock);
        evicted = add_to_cache(cache,new_cache_val);
        cachestring = evict_cache_message(evicted,new_cache_val);
        pthread_mutex_unlock(&cachelock);
        write_log_message(cachestring);
    }


    /* log response from upstream*/
    logstring = get_log_message(out_message);
    write_log_message(logstring);

    /* forward message to client */
    write_tcp_to_socket(newsockfd_inc,upsbuffer,out_mes_len);
    printf("(%d) sent response to client\n",newsockfd_inc);
    close(newsockfd_inc);
    return NULL;

}

/* reads a response packet from a socket, stores size in pointer */
uint8_t *read_tcp_from_socket(int sockfd,int *sizeptr) {
    uint8_t *buffer;
    int current_len=0,bytes_to_read=0,bytes_read=0;

    // allocate memory for two byte tcp size header
    buffer = malloc(TCP_SIZE_HEADER*sizeof(uint8_t));

    // read two byte size header
    current_len += read(sockfd,buffer,TCP_SIZE_HEADER);

    // get number of bytes of the remaining message
    //bytes_to_read = buffer[0]<<8 | buffer[1];
    bytes_to_read = ntohs(*(uint16_t*)buffer);
    //bytes_to_read = *(uint16_t*)buffer;
    //*(uint16_t*)buffer = htons(*(uint16_t*)buffer);
    buffer = realloc(buffer,(bytes_to_read+TCP_SIZE_HEADER)*sizeof(uint8_t));


    // read rest of message
    while (true) {
        bytes_read=read(sockfd,&buffer[current_len],bytes_to_read);
        if (bytes_read < 0) {
            return NULL;
        }
        bytes_to_read-=bytes_read;
        current_len+=bytes_read;
        if (bytes_to_read == 0) {
            break;
        }
    }

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
        if (bytes_written < 0) {
            fprintf(stderr,"Failed to write to socket (%d)\n",sockfd);
            return;
        }
        bytes_rem-=bytes_written;
        bytes_sent+=bytes_written;
        if(bytes_rem==0) {
            return;
        }
    }
}

/* sets up listening socket */
int setup_listening_socket(void) {
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


void write_log_message(char *message) {
    if (message==NULL) return;
    pthread_mutex_lock(&filelock);
    FILE *fp = fopen(LOG_FILE_PATH,"a");
    fprintf(fp,"%s",message);
    fflush(fp);
    fclose(fp);
    pthread_mutex_unlock(&filelock);
}

