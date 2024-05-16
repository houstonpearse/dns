/* 
 * phase 1 by Houston Pearse 994653  
 * for COMP30023 project 2
*/

#include "dns_message.h"

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

void hex_dump(uint8_t *packet,int packet_size);
void binary_dump(uint8_t *packet,int packet_size);

//void print_binary(uint8_t n);
void print_hex(uint8_t n);

int main(int argc, char* argv[]) {
    uint8_t *packet,size_buffer[2];
    int packet_size,isreply;

    /* get size from the first two bytes */
    read(STDIN_FILENO, size_buffer, 2);


    /* 1st byte 0x9F is left shifted to by 8 bits to become 0x9F00 */
    /* 2nd byte 0xA2 is concatenated (|)to the first byte to get 0x9FA2 with */
    packet_size = (size_buffer[0]<<8)|(size_buffer[1]);

    /* read rest of packet */
    packet = malloc(packet_size*sizeof(*packet));
    read(STDIN_FILENO,packet,packet_size);

    dns_message_t *message = new_dns_message(packet,packet_size);
    printf("%s",get_log_message(message));
    //set_parameters(packet,packet_size);


    /*
    // print
    print_message(message);
    hex_dump(packet,packet_size);
    //binary_dump(packet,packet_size);
    */

    return 0; 
}

/************************************************************************/

