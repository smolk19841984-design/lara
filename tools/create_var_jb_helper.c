// create_var_jb_helper.c
// Минималистичный helper для TrustCache pipeline
// Создаёт /var/jb с правами 0755, возвращает 0 при успехе, иначе errno

#include <stdio.h>
#include <sys/stat.h>
#include <errno.h>

int main(void) {
    int res = mkdir("/var/jb", 0755);
    if (res == 0) {
        return 0;
    } else {
        return errno;
    }
}
