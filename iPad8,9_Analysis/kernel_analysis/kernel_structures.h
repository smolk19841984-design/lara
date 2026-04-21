// Kernel Structures - iPad8,9 iOS 17.3.1 (21D61)
// Runtime-confirmed offsets for T8020 (A12X Bionic)

/* thread_t - Main thread structure */
struct thread_t {
    uint64_t              t_ctr;                      // +0x000 - Thread base
    thread_ro *            t_tro;                     // +0x348 - Thread Read-Only pointer
    thread_t              task_threads_next;           // +0x348 - Next thread in task list (same as t_tro on T8020)
    uint32_t              thread_ast;                 // +0x38c - AST state
    lck_mtx_t             thread_mutex;               // +0x390 - Thread mutex
    uint64_t              thread_ctid;                  // +0x3f8 - Thread ID (tro + 0xB0)
    uint64_t              thread_guard_exc_info;        // +0x2f8 - Exception guard info (tro - 0x50)
};

/* thread_ro - Thread Read-Only structure */
struct thread_ro {
    thread_t *             thread_ptr;                  // +0x00  - Back-pointer to thread (iOS 17)
    task_t *               tro_task;                    // +0x?? - Task pointer
    proc_t *               tro_proc;                    // +0x?? - Process pointer
};

/* task_t - Main task structure */
struct task_t {
    uint64_t              task;                      // +0x00  - Task base
    thread_t *             threads;                   // +0x48  - Thread list head
    thread_t *             threads_next;             // +0x50  - Next thread (runtime confirmed)
};

