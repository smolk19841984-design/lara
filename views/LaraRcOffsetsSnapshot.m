//
//  LaraRcOffsetsSnapshot.m
//  lara
//

#import "LaraRcOffsetsSnapshot.h"
#import "kexploit/rc_offsets.h"
#include <sys/sysctl.h>

NSString *LaraRcOffsetsSnapshotString(void) {
    char machine[64] = {0};
    size_t mlen = sizeof(machine) - 1;
    sysctlbyname("hw.machine", machine, &mlen, NULL, 0);

    return [NSString stringWithFormat:
            @"hw.machine=%s\n"
            @"rc_off_thread_t_tro=0x%x\n"
            @"rc_off_thread_ro_tro_proc=0x%x\n"
            @"rc_off_thread_ro_tro_task=0x%x\n"
            @"rc_off_thread_ctid=0x%x\n"
            @"rc_off_thread_options=0x%x\n"
            @"rc_off_thread_mutex_lck_mtx_data=0x%x\n"
            @"rc_off_thread_machine_kstackptr=0x%x\n"
            @"rc_off_thread_machine_jop_pid=0x%x\n"
            @"rc_off_thread_machine_rop_pid=0x%x\n"
            @"rc_off_thread_ast=0x%x\n"
            @"rc_off_thread_task_threads_next=0x%x\n"
            @"rc_off_thread_guard_exc_info_code=0x%x\n"
            @"rc_off_task_itk_space=0x%x\n"
            @"rc_off_task_threads_next=0x%x\n"
            @"rc_off_task_task_exc_guard=0x%x\n"
            @"rc_off_task_map=0x%x\n"
            @"rc_off_ipc_space_is_table=0x%x\n"
            @"rc_off_ipc_entry_ie_object=0x%x\n"
            @"rc_off_ipc_port_ip_kobject=0x%x\n"
            @"rc_sizeof_ipc_entry=0x%x\n"
            @"rc_off_arm_kernel_saved_state_sp=0x%x\n"
            @"rc_off_proc_p_proc_ro=0x%x\n"
            @"rc_off_proc_ro_p_ucred=0x%x\n"
            @"rc_off_proc_ro_pr_task=0x%x\n"
            @"rc_off_ucred_cr_label=0x%x\n"
            @"rc_off_label_l_perpolicy_amfi=0x%x\n"
            @"rc_off_label_l_perpolicy_sandbox=0x%x\n",
            machine,
            rc_off_thread_t_tro,
            rc_off_thread_ro_tro_proc,
            rc_off_thread_ro_tro_task,
            rc_off_thread_ctid,
            rc_off_thread_options,
            rc_off_thread_mutex_lck_mtx_data,
            rc_off_thread_machine_kstackptr,
            rc_off_thread_machine_jop_pid,
            rc_off_thread_machine_rop_pid,
            rc_off_thread_ast,
            rc_off_thread_task_threads_next,
            rc_off_thread_guard_exc_info_code,
            rc_off_task_itk_space,
            rc_off_task_threads_next,
            rc_off_task_task_exc_guard,
            rc_off_task_map,
            rc_off_ipc_space_is_table,
            rc_off_ipc_entry_ie_object,
            rc_off_ipc_port_ip_kobject,
            rc_sizeof_ipc_entry,
            rc_off_arm_kernel_saved_state_sp,
            rc_off_proc_p_proc_ro,
            rc_off_proc_ro_p_ucred,
            rc_off_proc_ro_pr_task,
            rc_off_ucred_cr_label,
            rc_off_label_l_perpolicy_amfi,
            rc_off_label_l_perpolicy_sandbox];
}
