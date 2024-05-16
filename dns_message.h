#ifndef DNS_MESSAGE
#define DNS_MESSAGE


#include <stdint.h>
#include <stdbool.h>
#include <netdb.h>

#define LOGFILEPATH "dns_svr.log"


typedef struct header {
    uint16_t id;
    bool QR;
}header_t;

typedef struct question {
    char domn[240];
    bool is_AAAA;
}question_t;

typedef struct response {
    char ipadr[INET6_ADDRSTRLEN];
    bool is_AAAA;
}response_t;

typedef struct dns_message {
    int16_t nq,nr;
    header_t header;
    question_t question;
    response_t response;
}dns_message_t;

/* creates new dns message from a dns packet */
dns_message_t *new_dns_message(uint8_t *packet,int packet_size);

/* allocate memory for new dns_message */
dns_message_t *make_new_dns_message();

/* gets relevent infomation about dns header */
void get_header(dns_message_t *new_dns_message,uint8_t *packet,int packet_size);

/* returns offset for the end of the question */
int get_question(dns_message_t *new_dns_message,uint8_t *packet,int packet_size);

void get_response(int start,dns_message_t *new_dns_message,uint8_t *packet, int packet_size);

void print_message(dns_message_t *dns_message);

void write_to_log(dns_message_t *dns_message,int isreply);

void print_binary(uint8_t n);

void set_rcode(uint8_t *packet,int packet_size,int rcode);

#endif
