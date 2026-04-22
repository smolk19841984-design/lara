#include "curl.h"

#include <stdarg.h>

int curl_global_init(long flags) {
    (void)flags;
    return 0;
}

void curl_global_cleanup(void) {}

CURL *curl_easy_init(void) {
    return (CURL *)0x1;
}

void curl_easy_cleanup(CURL *handle) {
    (void)handle;
}

CURLcode curl_easy_setopt(CURL *handle, int option, ...) {
    (void)handle;
    (void)option;
    return CURLE_OK;
}

CURLcode curl_easy_perform(CURL *handle) {
    (void)handle;
    // Stub: network is unavailable.
    return 1;
}

const char *curl_easy_strerror(CURLcode code) {
    (void)code;
    return "curl stub";
}

