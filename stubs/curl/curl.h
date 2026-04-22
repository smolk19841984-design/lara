#pragma once

#include <stddef.h>

typedef void CURL;
typedef int CURLcode;

typedef size_t (*curl_write_callback)(void *contents, size_t size, size_t nmemb, void *userp);

#define CURL_GLOBAL_DEFAULT 0

#define CURLOPT_URL 10002
#define CURLOPT_WRITEFUNCTION 20011
#define CURLOPT_WRITEDATA 10001
#define CURLOPT_FOLLOWLOCATION 52

#define CURLE_OK 0

int curl_global_init(long flags);
void curl_global_cleanup(void);

CURL *curl_easy_init(void);
void curl_easy_cleanup(CURL *handle);

CURLcode curl_easy_setopt(CURL *handle, int option, ...);
CURLcode curl_easy_perform(CURL *handle);

const char *curl_easy_strerror(CURLcode code);

