#include "dns_message.h"

#include <netdb.h>
#include <time.h>

#define CACHE_SIZE 5
#define MAX_DOMNAME_LEN 240



typedef struct cache_item {
    char domn[MAX_DOMNAME_LEN];
    uint32_t TTL;
    uint8_t *packet;
    int packet_size;
}cache_item_t;

typedef struct cache {
    cache_item_t *cache_arr[CACHE_SIZE];
    time_t lastupdate;
}cache_t;

cache_item_t *new_cache_item(dns_message_t *message,uint8_t *packet,int packet_size);

cache_item_t *add_to_cache(cache_t cache,cache_item_t *new_cache_item);

cache_item_t *find_cache_item(cache_t cache,dns_message_t *inc_message);

void update_cache_ttl(cache_t cache);

char *evict_cache_message(cache_item_t *old,cache_item_t *new);

char *usage_cache_message(cache_item_t *cache_item);



