#import "libgrabkernel2.h"

#import <curl/curl.h>

static size_t _write_to_file(void *ptr, size_t size, size_t nmemb, void *userdata) {
    FILE *f = (FILE *)userdata;
    if (!f) return 0;
    return fwrite(ptr, size, nmemb, f);
}

bool grab_kernelcache(NSString *outPath) {
    if (!outPath.length) return false;

    const char *url = getenv("LARA_KERNELCACHE_URL");
    if (!url || url[0] == '\0') {
        // No default URL baked in; provide via env to keep behavior explicit.
        return false;
    }

    FILE *f = fopen(outPath.fileSystemRepresentation, "wb");
    if (!f) {
        return false;
    }

    CURL *curl = curl_easy_init();
    if (!curl) {
        fclose(f);
        return false;
    }

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, _write_to_file);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, f);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    fclose(f);

    return res == CURLE_OK;
}

