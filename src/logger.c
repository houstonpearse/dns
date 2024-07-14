#include "logger.h"
#include <pthread.h>
#include <syslog.h>
#include <time.h>
#include <string.h>
#include <stdarg.h>

/* logs will be truncated at MAX_LOG_LENGTH */
void logger(int priority, const char *format, ...) {
    va_list arglist;
    va_start(arglist, format);
    vsyslog(priority, format, arglist);
    
    
    // create input string
    char input[MAX_LOG_LENGTH] = "";
    int input_len=0;
    
    // get timestamp string
    time_t rawtime;
    struct tm *timeptr;
    char timestamp[MAX_LOG_LENGTH] = "";
    time(&rawtime);
    timeptr = localtime(&rawtime);
    strftime(timestamp, 120, "%FT%T%z", timeptr);

    // add thread id to string
    pthread_t id = pthread_self();
    size_t i;
    for (i = sizeof(i); i; i--) {
        input_len += sprintf(input+input_len,"%02x", *(((unsigned char*) &id) + i - 1));
    }

    // add timestamp to string
    input_len += sprintf(input + input_len," %s",timestamp);

    
    // add log level to string
    if (priority == LOG_DEBUG) {
        input_len+=sprintf(input+input_len," DEBUG ");
    } else if ( priority == LOG_INFO) {
        input_len+=sprintf(input+input_len," INFO ");
    } else if (priority == LOG_WARNING) {
        input_len+=sprintf(input+input_len," WARN ");
    } else if (priority == LOG_ERR) {
        input_len+=sprintf(input+input_len," ERROR ");
    }
    
    vsprintf(input+input_len,format,arglist);
    printf("%s",input);
    va_end(arglist);
}
