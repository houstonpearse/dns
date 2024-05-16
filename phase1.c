/* 
 * phase 1 by Houston Pearse 994653  
 * for COMP30023 project 2
*/

#include "dns_message.h"

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

void hex_dump(uint8_t *packet,int packet_size);
void binary_dump(uint8_t *packet,int packet_size);

void print_binary(uint8_t n);
void print_hex(uint8_t n);

int main(int argc, char* argv[]) {
    uint8_t *packet,size_buffer[2];
    int packet_size;

    /* get size from the first two bytes */
    read(STDIN_FILENO, size_buffer, 2);

    /* 1st byte 0x9F is left shifted to by 8 bits to become 0x9F00 */
    /* 2nd byte 0xA2 is concatenated (|)to the first byte to get 0x9FA2 with */
    packet_size = (size_buffer[0]<<8)|(size_buffer[1]);
    printf("decimal size: %d\n",packet_size);
    

    /* read rest of packet */
    packet = malloc(packet_size*sizeof(*packet));
    read(STDIN_FILENO,packet,packet_size);

    dns_message_t *message = new_dns_message(packet,packet_size);
    print_message(message);
    print_log(message);

    /* print packet */
    hex_dump(packet,packet_size);
    //binary_dump(packet,packet_size);

    return 0; 
}

/************************************************************************/

/** helper functions **/




void print_hex(uint8_t n) {
    printf("%02X ",n);
}

void print_binary(uint8_t n) {
    uint8_t i1 = (1 << (sizeof(n)*8-1));
    for(; i1; i1 >>= 1)
      printf("%d  ",(n&i1)!=0);
}

/* helper function to format result to inspect easily */
void hex_dump(uint8_t *packet,int packet_size) {
    int i,j;
    printf("-------------------------------------------------\n");
    printf("00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F |\n");
    printf("----------------------------------------------- |\n");
    
    i=0;
    for (j=0;j<packet_size;j++) {
        if(i==16) {
            i=0;
            printf("|\n");
        }
        print_hex(packet[j]);
        i++;
    }
    while (i!=16) {
        i++;
        printf("   ");
    }
    printf("|\n");
    printf("-------------------------------------------------\n");
}

void binary_dump(uint8_t *packet,int packet_size) {
    int i;
    printf("-------------------------------------------------\n");
    printf("0  1  2  3  4  5  6  7  8  9  10 11 12 13 14 15 |\n");
    printf("----------------------------------------------- |\n");
    for (i=0;i<packet_size;i++){
        print_binary(packet[i]);
        if (i%2==1){
            printf("|\n");
        }
        if(i==11) {
            printf("----------------------------------------------- |\n");
        }
    }
    if(i%2==1) {
        printf("                        |\n");
    }
    printf("-------------------------------------------------\n");
}
