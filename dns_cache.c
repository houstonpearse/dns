#include "dns_cache.h"

#include <string.h>
#include <time.h>

cache_item_t *new_cache_item(dns_message_t *message,uint8_t *packet,int packet_size) {
    cache_item_t *ci;
    ci = malloc(sizeof(*ci));
    strcpy(ci->domn,message->question.domn);
    ci->TTL = message->response.ttl;
    ci->packet = packet;
    ci->packet_size = packet_size;  
}

/* returns the old cache item evicted, returns NULL if none are evicted*/
cache_item_t *add_to_cache(cache_t cache,cache_item_t *new_cache_item) {
    int i;
    update_cache_ttl(cache);
    // see if there are any empty spaces
    for(i=0;i<CACHE_SIZE;i++) {
        if (cache.cache_arr[i]==NULL) {
            cache.cache_arr[i] = new_cache_item;
            return NULL;
        }
    }

    // no empty spaces found evict the shortest one
    int min=0;
    for(i=0;i<CACHE_SIZE;i++) {
        if (cache.cache_arr[i]->TTL<cache.cache_arr[min]->TTL) {
            min = i;
        }
    }

    cache_item_t *temp = cache.cache_arr[min];
    cache.cache_arr[min] = new_cache_item;
    return temp;

}

cache_item_t *find_cache_item(cache_t cache,dns_message_t *inc_message) {
    int i;
    update_cache_ttl(cache);
    for(i=0;i<CACHE_SIZE;i++) {
        if (strcmp(cache.cache_arr[i]->domn,inc_message->question.domn)==0) {
            return cache.cache_arr[i];
        }
    }
    return NULL;
}

void update_cache_ttl(cache_t cache) {
    int i;
    time_t t = time(NULL);
    int delta = (int)difftime(t,cache.lastupdate);
    cache.lastupdate = t;
    for(i=0;i<CACHE_SIZE;i++) {
        if (cache.cache_arr[i]!=NULL) {
            if ((int)(cache.cache_arr[i]->TTL) <= delta) {
                cache.cache_arr[i]->TTL = 0;
            } else {
                cache.cache_arr[i]->TTL = cache.cache_arr[i]->TTL - delta;
            }
        }
    }
}


char *usage_cache_message(cache_item_t *cache_item) {
    assert(cache_item!=NULL);
    // <timestamp> <domain_name> expires at <timestamp> 
    // – for each request you receive that is in your cache
    time_t rawtime;
    struct tm *timeptr;
    char timetemp[128] = "", log[512] = ""; 
    
    /* setup time stamp */
    time(&rawtime);
    timeptr = localtime(&rawtime);
    strftime(timetemp, 100, "%FT%T%z", timeptr);
    
    /* copy log message into temp string */
    sprintf(log,"%s %s expires at %s\n",timetemp,cache_item->domn,timetemp);
    
    /* allocate new string to return */
    char *str = malloc(strlen(log)*sizeof(*str));
    strcpy(str,log);
    return str;

}
char *evict_cache_message(cache_item_t *old,cache_item_t *new) {
    assert(old!=NULL && new!=NULL);
    char timetemp[128] = "", log[512] = ""; 
    time_t rawtime;
    struct tm *timeptr;
    
    /* setup time stamp */
    time(&rawtime);
    timeptr = localtime(&rawtime);
    strftime(timetemp, 100, "%FT%T%z", timeptr);
    
    /* copy log message into temp string */
    //<timestamp> replacing <domain_name> by <domain_name> 
    sprintf(log,"%s replacing %s by %s\n",timetemp,old->domn,new->domn);
    
    /* allocate new string to return */
    char *str = malloc(strlen(log)*sizeof(*str));
    strcpy(str,log);
    return str;
}
