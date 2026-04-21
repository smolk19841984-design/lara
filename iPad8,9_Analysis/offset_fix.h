
// OFFSET FIX BASED ON LOG ANALYSIS
// Best hypothesis: task_threads_next=0x48, tro=0x348, thread_next=0x348
// Score: 0.75

#ifdef __arm64__
    // A12X iOS 17.3.1 specific offsets
    rc_off_task_threads_next = 0x48;
    rc_off_thread_t_tro = 0x348;
    rc_off_thread_task_threads_next = 0x348;
#endif
