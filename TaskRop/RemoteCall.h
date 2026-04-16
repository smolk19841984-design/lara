#ifndef RemoteCall_h
#define RemoteCall_h

#import <mach/mach.h>

struct VMShmem {
    uint64_t port;
    uint64_t remoteAddress;
    uint64_t localAddress;
    bool     used;
};

// from Duy Tran's TaskPortHaxxApp
typedef struct {
    uint64_t __x[29];
    uint64_t __fp;
    uint64_t __lr;
    uint64_t __sp;
    uint64_t __pc;
    uint32_t __cpsr;
    uint32_t __flags;
} arm_thread_state64_internal;

mach_port_t create_exception_port(void);
int init_remote_call(const char *process, bool useMigFilterBypass);
uint64_t do_remote_call_temp(int timeout, const char *name, uint64_t x0, uint64_t x1, uint64_t x2, uint64_t x3, uint64_t x4, uint64_t x5, uint64_t x6, uint64_t x7);
uint64_t do_remote_call_stable(int timeout, const char *name, uint64_t x0, uint64_t x1, uint64_t x2, uint64_t x3, uint64_t x4, uint64_t x5, uint64_t x6, uint64_t x7);
void sign_state(uint64_t signingThread, arm_thread_state64_internal *state, uint64_t pc, uint64_t lr);
uint64_t remote_pac(uint64_t remoteThreadAddr, uint64_t address, uint64_t modifier);
bool remote_read(uint64_t src, void *dst, uint64_t size);
uint64_t remote_read64(uint64_t src);
bool remote_write(uint64_t dst, const void *src, uint64_t size);
bool remote_write64(uint64_t dst, uint64_t val);
bool remote_writeStr(uint64_t dst, const char *str);
void remote_hexdump(uint64_t remoteAddr, size_t size);
int destroy_remote_call(void);

extern uint64_t g_RC_taskAddr;
extern uint64_t g_RC_trojanMem;
extern uint64_t g_RC_trojanThreadAddr;
extern uint64_t g_RC_callThreadAddr;
extern uint64_t g_RC_vmMap;
extern bool     g_RC_creatingExtraThread;
extern uint64_t g_RC_gadgetPacia;

#endif /* RemoteCall_h */
