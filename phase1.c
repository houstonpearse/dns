/* 
 * phase 1 by Houston Pearse 994653  
 * for COMP30023 project 2
*/

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

void hex_print(uint8_t *packet,int packet_size);

int main(int argc, char* argv[]) {
    uint8_t *packet,size_buffer[2];
    int packet_size;

    /* get size from the first two bytes */
    read(STDIN_FILENO, size_buffer, 2);

    /* 1st byte 0x9F is left shifted to by 8 bits to become 0x9F00 */
    /* 2nd byte 0xA2 is concaternated to the first byte to get 0x9FA2 */
    packet_size = (size_buffer[0]<<8)|(size_buffer[1]);
    printf("decimal size: %d\n",packet_size);

    /* read rest of packet */
    packet = malloc(packet_size*sizeof(*packet));
    read(STDIN_FILENO,packet,packet_size);

    /* print packet */
    hex_print(packet,packet_size);

    return 0; 
}

/************************************************************************/

/** helper functions **/

/* helper function to format result to inspect easily */
void hex_print(uint8_t *packet,int packet_size) {
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
        printf("%02X ",packet[j]);
        i++;
    }
    while (i!=16) {
        i++;
        printf("   ");
    }
    printf("|\n");
    printf("-------------------------------------------------\n");
}
