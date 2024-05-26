#include "connection.h"
#include "dns_message.h"
#include "dns_cache.h"
#include <ctype.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#define LOG_FILE_PATH "dns_svr.log"
#define MAX_RETRIES 2

void *handle_new_connection(void *args);
void write_log_message(char *message);
struct arguments {
    cache_t *cache;
    int client_con_fd;
    connection_t *upstream_connection;
};

pthread_mutex_t cachelock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t connectionlock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t filelock = PTHREAD_MUTEX_INITIALIZER;

int main(int argc,char** argv) {
    int listen_socket_fd,client_con_fd;
    cache_t *cache;
    struct arguments *args;
    connection_t upstream_connnection;

    /* the ip and port of the server the messages will be forwarded to */
    if (argc < 3) {
		fprintf(stderr, "usage %s serverIP port\n", argv[0]);
		exit(EXIT_FAILURE);
	}

    /* setup cache */
    cache = malloc(sizeof(*cache));
    cache->lastupdate = time(NULL);

    printf("-----------------------IPV6-DNS-----------------------\n");
    upstream_connnection.socket = connection(argv[1], atoi(argv[2]),SOCK_STREAM);
    upstream_connnection.socket_type = SOCK_STREAM;
    upstream_connnection.port = atoi(argv[2]);
    strcpy(upstream_connnection.ip,argv[1]); 

    listen_socket_fd = listening_socket(8053,20);
    printf("listening for connections on port %d\n",8053);
    while(true) {
        client_con_fd = accept(listen_socket_fd, NULL, NULL);
        if (client_con_fd < 0) {
            perror("accept");
            exit(EXIT_FAILURE);
        }
        printf("accepted a new connection. socketfd = %d\n",client_con_fd);
        args = malloc(sizeof(*args));
        args->cache = cache;
        args->client_con_fd = client_con_fd;
        args->upstream_connection = &upstream_connnection;
        pthread_t t;
        pthread_create(&t,NULL,handle_new_connection,args);
    }
    close(listen_socket_fd);
}

/**************** helpers *****************/

/* handles new connections */
void *handle_new_connection(void *args) {
    // unpack args from struct and free struct
    cache_t *cache = ((struct arguments*)args)->cache;
    int client_con_fd = ((struct arguments*)args)->client_con_fd;
    connection_t *upstream_connection = ((struct arguments*)args)->upstream_connection;
    free(args);

    int i,inc_mes_len,out_mes_len,bytes_written;
    uint8_t *cbuffer,*upsbuffer;
    dns_message_t *out_message,*inc_message;
    cache_item_t *cache_search_val,*new_cache_val,*evicted;
    char *logstring,*cachestring;

    printf("(%d) Reading client message\n",client_con_fd);
    cbuffer = read_tcp(client_con_fd,&inc_mes_len);
    inc_message = new_dns_message(&cbuffer[2],inc_mes_len-2);
    if (inc_message == NULL) {
        printf("(%d) Invalid DNS Query\n",client_con_fd);
        pthread_mutex_unlock(&cachelock);
        close(client_con_fd);
        return NULL;
    } 

    printf("(%d) Received client request\n",client_con_fd);
    logstring = get_log_message(inc_message);
    write_log_message(logstring);
    
    if(inc_message->question.is_AAAA == false) {
        printf("(%d) IPV4 Request Not Implemented.\n",client_con_fd);
        set_packet_headers(&cbuffer[2],inc_mes_len-2,-1,1,4,1);
        write_buffer(client_con_fd,cbuffer,inc_mes_len);
        close(client_con_fd);
        return NULL;
    } 

    pthread_mutex_lock(&cachelock);
    cache_search_val = find_cache_item(cache,inc_message->question.domn);
    if (cache_search_val != NULL && cache_search_val->ttl>0) {
        printf("(%d) Cache hit for %s\n",client_con_fd,inc_message->question.domn);
        
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
        write_buffer(client_con_fd,upsbuffer,out_mes_len);
        close(client_con_fd);
        pthread_mutex_unlock(&cachelock);
        return NULL;
    }
    pthread_mutex_unlock(&cachelock);
    
    /* forward AAAA query to upstream server */
    printf("(%d) Forwarding message to upstream server\n",client_con_fd);
    pthread_mutex_lock(&connectionlock);
    int attempts=0;
    while (attempts<MAX_RETRIES) {
        attempts++;
        bytes_written = write_buffer(upstream_connection->socket,cbuffer,inc_mes_len);
        upsbuffer = read_tcp(upstream_connection->socket,&out_mes_len); 
        if (upsbuffer == NULL || bytes_written<inc_mes_len) {
            printf("(%d) Failed to communicate to upstream server. Retrying.\n",client_con_fd);
            close(upstream_connection->socket);
            upstream_connection->socket = connection(upstream_connection->ip,upstream_connection->port,upstream_connection->socket_type);
        } else {
            break;
        }
    }
    pthread_mutex_unlock(&connectionlock);

    /* check for success */
    if (upsbuffer == NULL || bytes_written < inc_mes_len) {
        printf("(%d) Failed to communicate with upstream server\n",client_con_fd);
        set_packet_headers(&cbuffer[2],inc_mes_len-2,-1,1,2,-1);
        write_buffer(client_con_fd,cbuffer,inc_mes_len); 
        close(client_con_fd);
        return NULL;
    };
    
    
    /* read upstream response */
    out_message = new_dns_message(&upsbuffer[2],out_mes_len-2);
    if (out_message == NULL) {
        printf("(%d) Received an unknown response from upstream server\n",client_con_fd);
        set_packet_headers(&cbuffer[2],inc_mes_len-2,-1,1,2,-1);
        write_buffer(client_con_fd,cbuffer,inc_mes_len);
        close(client_con_fd);
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
    write_buffer(client_con_fd,upsbuffer,out_mes_len);
    printf("(%d) sent response to client\n",client_con_fd);
    close(client_con_fd);
    return NULL;

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

