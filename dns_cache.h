#ifndef DNS_CACHING
#define DNS_CACHING

#include <stdint.h>
#include <time.h>

#define SIZE 5
#define MAX_DOMNAME_LEN 240



typedef struct cache_item {
    char domn[MAX_DOMNAME_LEN];
    uint32_t TTL;
    uint8_t *packet;
    int packet_size;
}cache_item_t;

typedef struct cache {
    cache_item_t *cache_arr[SIZE];
    time_t lastupdate;
}cache_t;

cache_item_t *new_cache_item(char *domname,uint32_t ttl,uint8_t *packet,int packet_size);

cache_item_t *add_to_cache(cache_t cache,cache_item_t *new_cache_item);

cache_item_t *find_cache_item(cache_t cache,char *domname);

void update_cache_ttl(cache_t cache);

char *evict_cache_message(cache_item_t *old,cache_item_t *new);

char *usage_cache_message(cache_item_t *cache_item);



#endif
