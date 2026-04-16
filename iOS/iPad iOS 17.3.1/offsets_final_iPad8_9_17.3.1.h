/* Final offsets header for iPad8,9 iOS 17.3.1 kernelcache */
#ifndef OFFSETS_IPAD8_9_17_3_1_FINAL_H
#define OFFSETS_IPAD8_9_17_3_1_FINAL_H

#define KERNEL_BASE 0xfffffff007004000
#define SYM_PANIC 0xfffffff0079f65b0
#define SYM_AMFI  0xfffffff007c86ae0

/* Signature blobs (32 bytes) extracted from kernel image */
#define SIG_PANIC_BYTES "\x1c\x94\x79\x01\x5f\x06\x11\x80\xc0\x99\x79\x01\x99\x23\x11\x80\x34\x9b\x79\x01\x59\xd7\x11\x80\x48\x9b\x79\x01\x2d\x57\x11\x80"
#define SIG_AMFI_BYTES  "\x24\xb1\x35\x01\x8d\xd7\x11\x80\x58\xb0\x35\x01\x1d\x3a\x11\x80\x6c\xaf\x35\x01\x90\xa3\x11\x80\xb4\xae\x35\x01\x0b\x24\x11\x80"

/* Masked signature hex (?? = wildcard for bytes likely containing pointers) */
#define SIG_PANIC_MASKED_HEX "1c9479015f061180c099790199231180349b790159d71180489b79012d571180"
#define SIG_AMFI_MASKED_HEX  "24b135018dd7118058b035011d3a11806caf350190a31180b4ae35010b241180"

#endif // OFFSETS_IPAD8_9_17_3_1_FINAL_H
