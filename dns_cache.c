#include "dns_cache.h"

#include <netdb.h>
#include <time.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#define MAX_TIMESTAMP_LEN 128
#define MAX_LOGLINE_LENGTH 700

cache_item_t *new_cache_item(char *domname,uint32_t ttl,uint8_t *buffer,int buffer_size) {
    cache_item_t *ci;
    ci = malloc(sizeof(*ci));
    strcpy(ci->domn,domname);
    ci->ttl = ttl;
    ci->buffer = buffer;
    ci->buffer_size = buffer_size;
    return ci;
}

/* returns the old cache item evicted, returns NULL if none are evicted*/
cache_item_t *add_to_cache(cache_t *cache,cache_item_t *new_cache_item) {
    int i;
    cache_item_t *temp1,*temp2;
    update_cache_ttl(cache);
    // always evict 0 items with 0 length
    for(i=0;i<SIZE;i++) {
        if (cache->cache_arr[i]!=NULL && cache->cache_arr[i]->ttl==0) {
            temp1 = cache->cache_arr[i];
            cache->cache_arr[i] = new_cache_item;
            return temp1;
        }
    }
    // see if there are any empty spaces
    for(i=0;i<SIZE;i++) {
        if (cache->cache_arr[i]==NULL) {
            cache->cache_arr[i] = new_cache_item;
            return NULL;
        }
    }

    // no empty spaces found evict the shortest one
    int min=0;
    for(i=0;i<SIZE;i++) {
        if (cache->cache_arr[i]->ttl<cache->cache_arr[min]->ttl) {
            min = i;
        }
    }

    temp2 = cache->cache_arr[min];
    cache->cache_arr[min] = new_cache_item;
    return temp2;

}

/* finds a cache entry for a domain name */
cache_item_t *find_cache_item(cache_t *cache,char *domname) {
    int i;
    update_cache_ttl(cache);
    for(i=0;i<SIZE;i++) {
        if ((cache->cache_arr[i]!=NULL)&&
            (strcmp(cache->cache_arr[i]->domn,domname)==0)) {
            return cache->cache_arr[i];
        }
    }
    return NULL;
}

/* updates the cache entries ttl */
void update_cache_ttl(cache_t *cache) {
    int i;
    time_t t = time(NULL);
    int delta = (int)difftime(t,cache->lastupdate);
    cache->lastupdate = t;
    for(i=0;i<SIZE;i++) {
        if (cache->cache_arr[i]!=NULL) {
            if ((int)(cache->cache_arr[i]->ttl) <= delta) {
                cache->cache_arr[i]->ttl = 0;
            } else {
                cache->cache_arr[i]->ttl = cache->cache_arr[i]->ttl - delta;
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
    char timetemp[MAX_TIMESTAMP_LEN] = "", log[MAX_LOGLINE_LENGTH] = ""; 
    
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
    assert(new!=NULL);
    if (old==NULL) return NULL;
    char timetemp[MAX_TIMESTAMP_LEN] = "", log[MAX_LOGLINE_LENGTH] = ""; 
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
