#include <stdlib.h>

#define TCP_SIZE_HEADER_LENGTH 2

typedef struct connection {
    int socket;
    int socket_type;
    char ip[16];
    int port;
} connection_t;

uint8_t *read_tcp(int sockfd,int *sizeptr);
uint8_t *send_request(struct connection *conn, uint8_t *buffer, int buffer_len, int *response_len, int retry);
int read_buffer(int sockfd, uint8_t *buffer,int buffer_pos, int buffer_size);
int write_buffer(int sockfd, uint8_t *buffer,int buffer_size);
int listening_socket(int port, int queue_size);
int connection(struct connection *conn);
int reconnect(struct connection *conn);
