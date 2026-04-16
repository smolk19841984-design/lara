#import <mach/mach.h>
#import "RemoteCall.h"

// xnu-10002.81.5/osfmk/mach/port.h
#define MPO_PROVISIONAL_ID_PROT_OPTOUT  0x8000

// from pe_main.js
#define EXCEPTION_MSG_SIZE   0x160
#define EXCEPTION_REPLY_SIZE 0x13c

typedef struct {
    mach_msg_header_t            Head;
    uint64_t                     NDR;
    uint32_t                     exception;
    uint32_t                     codeCnt;
    uint64_t                     codeFirst;
    uint64_t                     codeSecond;
    uint32_t                     flavor;
    uint32_t                     old_stateCnt;
    arm_thread_state64_internal  threadState;
    uint64_t                     padding[2];
} ExceptionMessage;

typedef struct {
    mach_msg_header_t            Head;
    uint64_t                     NDR;
    uint32_t                     RetCode;
    uint32_t                     flavor;
    uint32_t                     new_stateCnt;
    arm_thread_state64_internal  threadState;
} __attribute__((packed)) ExceptionReply;

mach_port_t create_exception_port(void);
bool        wait_exception(mach_port_t exceptionPort, ExceptionMessage *excBuffer, int timeout, bool debug);
void        reply_with_state(ExceptionMessage *exc, arm_thread_state64_internal *state);
