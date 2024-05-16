#include "dns_message.h"

#include <stdint.h>
#include <time.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <netdb.h>
#include <arpa/inet.h>



/* creates new dns message from a dns packet */
dns_message_t *new_dns_message(uint8_t *packet,int packet_size) {
    int offset;

    dns_message_t *message = make_new_dns_message();
    get_header(message,packet,packet_size);
    offset = get_question(message,packet,packet_size);
    if (message->question.is_AAAA && message->nr>=1) {
        get_response(offset,message,packet,packet_size);
    }
    return message;

}
/* allocate memory for new dns_message */
dns_message_t *make_new_dns_message() {
    dns_message_t *new_dns_message = malloc(sizeof(dns_message_t));
    return new_dns_message;
}

/* set Rcode */

void set_rcode(uint8_t *packet,int packet_size,int rcode) {
    assert(packet_size>4);
    assert(rcode<16);

    uint8_t val = packet[3];

    print_binary(val);
    val = ((val>>4)<<4) + rcode;
    print_binary(val);
}

/* gets relevent infomation about dns header */
void get_header(dns_message_t *new_dns_message,uint8_t *packet,int packet_size) {
    assert(packet_size>12);

    /* we get id from first two bytes */
    new_dns_message->header.id = (packet[0]<<8)|(packet[1]);
    /* find out if this packet is a question or response*/
    new_dns_message->header.QR = (packet[2]>=128);
    /* nq */
    new_dns_message->nq = (packet[4]<<8)|(packet[5]);
    /* nr */
    new_dns_message->nr = (packet[6]<<8)|(packet[7]);
}

/* returns offset for the end of the question */
int get_question(dns_message_t *new_dns_message,uint8_t *packet,int packet_size) {
    int i,url_pos,sec_len,start,stop;
    char temp;

    /* the length of the first url section will be at the 12th byte*/
    sec_len = packet[12];
    /* initial position of next character insertion */
    url_pos = 0;
    /* characters of the first url section start at the 13th byte */ 
    start = 13;
    /* we will stop reading at after we have read sec_len bytes */
    stop = start + sec_len;

    /* keep reading sections untill we get a section of 0 length*/
    while (sec_len>0) {
        /* loop through the sections bytes and construct the url */
        for(i=start;i<stop;i++) {
            /* cast from 8 bit int to char */
            temp = (char)packet[i];
            /* insert */
            new_dns_message->question.domn[url_pos]=temp;
            /* move to next spot in string */
            url_pos++;
        }
        /* append a '.' after each section */
        new_dns_message->question.domn[url_pos] = '.';
        url_pos++;
        /* get length of next section */
        sec_len = packet[stop];
        /* next start is one after the current stop */
        start = stop + 1;
        /* new stop point for new section */
        stop = start + sec_len;
    }

    /* swap last '.' for a null byte */
    new_dns_message->question.domn[url_pos-1] = '\0';

    /* read question type AAAA or A */
    new_dns_message->question.is_AAAA=(((packet[start]<<8)|(packet[start+1]))==28);
    start+=2;

    /* skip Qtype */
    start+=2;

    return start;
}

void get_response(int start,dns_message_t *new_dns_message,uint8_t *packet, int packet_size) {
    int i,rlen;
    uint8_t ip[16];

    /* init string with null byte */
    new_dns_message->response.ipadr[0] = '\0';

    assert(packet_size>start + 12);
    /* skip Aname */
    start+=2;

    /* get Atype AAAA or A ect */
    new_dns_message->response.is_AAAA = (((packet[start]<<8)|(packet[start+1]))==28);
    start+=2;

    /* skip class */
    start+=2;

    /* skip TTL */
    start+=4;

    /* get response length */
    rlen = (packet[start]<<8)|(packet[start+1]);
    start+=2;

    
    assert(packet_size>=start+rlen);
    assert(rlen == 16);
    
    /* read byte string */
    for (i=0;i<16;i+=1) {
        ip[i] = packet[start+i];
    }

    /* convert byte string into ip address */
    inet_ntop(AF_INET6,ip,new_dns_message->response.ipadr,INET6_ADDRSTRLEN);
    
}

void print_message(dns_message_t *dns_message) {
    printf("\n------------- header -------------\n");
    printf("ID: %x",dns_message->header.id);
    printf(" ,QR: %d",dns_message->header.QR);
    printf(" ,NQ: %d",dns_message->nq);
    printf(" ,NA: %d\n",dns_message->nr);

    printf("--------------- question -----------\n");
    printf("URL: %s",dns_message->question.domn);
    printf(" ,AAAA: %d\n",dns_message->question.is_AAAA);

    if (dns_message->nr>0) {
        printf("--------------- response -----------\n");
        printf("IPv6: %s\n",dns_message->response.ipadr);
    }
    printf("\n");
}


void write_to_log(dns_message_t *dns_message,int isreply) {
    /* dont write to the log if its a reply with no answer */
    if(isreply && dns_message->nr == 0) {
        return;
    }

    FILE *fp = fopen(LOGFILEPATH,"a");
    time_t rawtime;
    struct tm *timeptr;
    char timetemp[100+1] = "",log[500] = "", temp[500]  = ""; 
    
    time(&rawtime);
    timeptr = localtime(&rawtime);
    strftime(timetemp, 100, "%FT%T%z", timeptr);

    strcat(log,timetemp);
    


    // write request or response to log
    if (dns_message->header.QR == 0) {
        // is a query
        sprintf(temp," requested %s\n",dns_message->question.domn);
        strcat(log,temp);
    } else {
        // is a response
        sprintf(temp," %s is at %s\n",dns_message->question.domn,dns_message->response.ipadr);
        strcat(log,temp);
    }
    printf("%s",log);
    fprintf(fp,"%s",log);

    // if message was not an AAAA then add extra line to log
    if (dns_message->question.is_AAAA == false) {
        //reset log string
        log[0]=0;
        // add timestamp to log
        strcpy(log,timetemp);
        // add message to log
        strcpy(temp," unimplemented request\n");
        strcat(log,temp);
        printf("%s",log);
        fprintf(fp,"%s",log);
    }
    
    fflush(fp);
    fclose(fp);
    //<timestamp> <domain_name> expires at <timestamp> – for each request you receive that is in your cache
    //<timestamp> replacing <domain_name> by <domain_name> – for each cache eviction
    
}

void print_binary(uint8_t n) {
    uint8_t i1 = (1 << (sizeof(n)*8-1));
    for(; i1; i1 >>= 1) {
      printf("%d  ",(n&i1)!=0);
    }
    printf("\n");
}

