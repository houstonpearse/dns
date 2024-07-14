#include "connection.h"
#include "dns_message.h"
#include "dns_cache.h"
#include "logger.h"
#include <stdio.h>
#include <ctype.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <syslog.h>

#define CONNECTION_RETRY 3
#define PORT 8053
#define CONNECTION_QUEUE_SIZE 20

void *handle_new_connection(void *args);
struct arguments {
    FILE *logfd;
    cache_t *cache;
    int client_con_fd;
    connection_t *upstream_con;
};

pthread_mutex_t cachelock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t connectionlock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t filelock = PTHREAD_MUTEX_INITIALIZER;

int main(int argc,char** argv) {
    int listen_socket_fd,client_con_fd;
    cache_t *cache;
    struct arguments *args;
    connection_t upstream_con = {0};
    
    /* the ip and port of the server the messages will be forwarded to */
    if (argc < 3) {
		fprintf(stderr, "usage %s serverIP port\n", argv[0]);
		exit(EXIT_FAILURE);
	}

    /* connection parameters */
    signal(SIGPIPE, SIG_IGN); // ignore sigpipe errors
    upstream_con.socket_type = SOCK_STREAM;
    upstream_con.port = atoi(argv[2]);
    strcpy(upstream_con.ip,argv[1]); 

    /* setup cache */
    cache = malloc(sizeof(*cache));
    cache->lastupdate = time(NULL);

    printf("------------------------DNS------------------------\n");
    listen_socket_fd = listening_socket(PORT,CONNECTION_QUEUE_SIZE);
    connection(&upstream_con);
    logger(LOG_DEBUG,"listening for connections on port %d\n",PORT);
    while(true) {
        client_con_fd = accept(listen_socket_fd, NULL, NULL);
        if (client_con_fd < 0) {
            perror("accept");
            exit(EXIT_FAILURE);
        }
        logger(LOG_DEBUG,"accepted a new connection. socketfd = %d\n",client_con_fd);
        args = malloc(sizeof(*args));
        args->cache = cache;
        args->client_con_fd = client_con_fd;
        args->upstream_con = &upstream_con;
        pthread_t t;
        pthread_create(&t,NULL,handle_new_connection,args);
    }
    close(listen_socket_fd);
}

void *handle_new_connection(void *args) {
    cache_t *cache = ((struct arguments*)args)->cache;
    int client_con_fd = ((struct arguments*)args)->client_con_fd;
    connection_t *upstream_con = ((struct arguments*)args)->upstream_con;
    free(args);

    int i,req_buffer_len,res_buffer_len;
    uint8_t *req_buffer,*res_buffer;
    dns_message_t *req_message,*res_message;
    cache_item_t *cache_search_val,*new_cache_val,*evicted;
    char *logstring,*cachestring;

    logger(LOG_DEBUG,"Reading client message\n");
    req_buffer = read_tcp(client_con_fd,&req_buffer_len);
    req_message = new_dns_message(&req_buffer[2],req_buffer_len-2);
    if (req_message == NULL) {
        logger(LOG_DEBUG,"Invalid DNS Query\n");
        pthread_mutex_unlock(&cachelock);
        close(client_con_fd);
        return NULL;
    } 
    logstring = get_log_message(req_message);
    logger(LOG_INFO,"%s",logstring);
    
    if(req_message->question.is_AAAA == false) {
        logger(LOG_DEBUG,"IPV4 Request Not Implemented.\n");
        set_packet_headers(&req_buffer[2],req_buffer_len-2,-1,1,4,1);
        write_buffer(client_con_fd,req_buffer,req_buffer_len);
        close(client_con_fd);
        return NULL;
    } 

    pthread_mutex_lock(&cachelock);
    cache_search_val = find_cache_item(cache,req_message->question.domn);
    if (cache_search_val != NULL && cache_search_val->ttl>0) {
        logger(LOG_DEBUG,"Cache hit for %s\n",client_con_fd,req_message->question.domn);
        
        // copy buffer from cache
        res_buffer = malloc(cache_search_val->buffer_size*sizeof(*res_buffer));
        res_buffer_len = cache_search_val->buffer_size;
        for (i=0;i<res_buffer_len;i++) {
            res_buffer[i]=cache_search_val->buffer[i];
        }
    
        // edit ttl and id bytes in the cached copy
        set_packet_headers(&res_buffer[2],res_buffer_len-2,req_message->header.id,-1,-1,-1);
        set_answer_ttl(&res_buffer[2],res_buffer_len-2,cache_search_val->ttl);

        // log event
        cachestring = usage_cache_message(cache_search_val);
        logger(LOG_INFO,"%s",cachestring);
        logger(LOG_INFO,"%s",get_log_message(new_dns_message(&res_buffer[2],res_buffer_len-2)));
        
        // send back response
        write_buffer(client_con_fd,res_buffer,res_buffer_len);
        close(client_con_fd);
        pthread_mutex_unlock(&cachelock);
        return NULL;
    }
    pthread_mutex_unlock(&cachelock);
    
    /* forward AAAA query to upstream server */
    pthread_mutex_lock(&connectionlock);
    logger(LOG_DEBUG,"connection lock\n");
    res_buffer = send_request(upstream_con,req_buffer,req_buffer_len,&res_buffer_len,CONNECTION_RETRY);
    logger(LOG_DEBUG,"connection unlock\n");
    pthread_mutex_unlock(&connectionlock);

    /* check for success */
    if (res_buffer == NULL) {
        logger(LOG_DEBUG,"Failed to communicate with upstream server. Setting SERVERROR flag\n");
        set_packet_headers(&req_buffer[2],req_buffer_len-2,-1,1,2,-1);
        write_buffer(client_con_fd,req_buffer,req_buffer_len); 
        close(client_con_fd);
        return NULL;
    };
    
    /* read upstream response */
    res_message = new_dns_message(&res_buffer[2],res_buffer_len-2);
    if (res_message == NULL) {
        logger(LOG_DEBUG,"Received an unknown response from upstream server\n");
        set_packet_headers(&req_buffer[2],req_buffer_len-2,-1,1,2,-1);
        write_buffer(client_con_fd,req_buffer,req_buffer_len);
        close(client_con_fd);
        return NULL;
    }

    /* add to cache if we have an answer */
    if (res_message->nr>0) {
        new_cache_val = new_cache_item(res_message->question.domn,
            res_message->response.ttl,
            res_buffer,
            res_buffer_len
        );
        pthread_mutex_lock(&cachelock);
        evicted = add_to_cache(cache,new_cache_val);
        cachestring = evict_cache_message(evicted,new_cache_val);
        pthread_mutex_unlock(&cachelock);
        if (cachestring!=NULL) logger(LOG_INFO,"%s",cachestring);
    }

    /* log response from upstream*/
    logstring = get_log_message(res_message);
    logger(LOG_INFO,"%s",logstring);

    /* forward message to client */
    write_buffer(client_con_fd,res_buffer,res_buffer_len);
    logger(LOG_DEBUG,"sent response to client\n");
    close(client_con_fd);
    return NULL;
}
