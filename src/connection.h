#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>
#include <ctype.h>

#define TCP_SIZE_HEADER_LENGTH 2

uint8_t *read_tcp(int sockfd,int *sizeptr);
int write_buffer(int sockfd, uint8_t *buffer,int buffer_size);
int listening_socket(int port, int queue_size);
int tcp_connection(char ip[],char port[]);
