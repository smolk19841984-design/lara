#import <stdbool.h>
#import <stdint.h>
#import <mach/mach.h>
#import "RemoteCall.h"

// inject / clear a guard exception on a victim kernel thread
bool inject_guard_exception(uint64_t thread, uint64_t code);
void clear_guard_exception(uint64_t thread);

// thin wrappers around thread_get_state / thread_set_state / thread_resume
bool thread_get_state_wrapper(mach_port_t machThread, arm_thread_state64_internal *outState);
bool thread_set_state_wrapper(mach_port_t machThread, uint64_t threadAddr, arm_thread_state64_internal *state);
bool thread_resume_wrapper(mach_port_t machThread);

// write PAC key slots (rop_pid/jop_pid) into a remote thread
void thread_set_pac_keys(uint64_t threadAddr, uint64_t keyA, uint64_t keyB);
