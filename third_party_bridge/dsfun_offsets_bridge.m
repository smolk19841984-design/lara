//
//  dsfun_offsets_bridge.m
//  lara — мост между Lara rc_offsets и third_party off_*
//

#import "../kexploit/rc_offsets.h"
#import "../kexploit/darksword.h"
#import "../kexploit/kcompat.h"

// ── kgetoffset: маппинг KOFFSET_* → Lara rc_offsets ─────────────────────────
// KOFFSET_* enum уже определён в compat.h (через -include)

uint32_t kgetoffset(KOffset off) {
    switch (off) {
        case KOFFSET_PROC_TASK:          return rc_off_proc_ro_pr_task;
        case KOFFSET_PROC_P_NAME:        return 0x100;
        case KOFFSET_TASK_CS_FLAGS:      return 0x5B0;
        case KOFFSET_ALLPROC:            return 0;
        case KOFFSET_PROC_PID:           return 0x10;
        case KOFFSET_PROC_P_FLAG:        return 0x18;
        case KOFFSET_PROC_P_TEXTVP:      return 0x68;
        case KOFFSET_PROC_P_FD:          return 0x40;
        case KOFFSET_FILEDESC_FD_CDIR:   return 0x10;
        case KOFFSET_VNODE_V_DATA:       return 0x88;
        case KOFFSET_VNODE_V_PARENT:     return 0x70;
        case KOFFSET_TTBR0_EL1:          return 0;
        case KOFFSET_TTBR1_EL1:          return 0;
        case KOFFSET_PPL_ZONE:           return 0;
        case KOFFSET_PPL_CHECK:          return 0;
        case KOFFSET_KERNEL_BASE:        return 0;
        default:                         return 0;
    }
}

uint64_t kgetoffset_by_name(const char *name) {
    (void)name;
    return 0;
}

// ── off_* aliases → rc_off_* ─────────────────────────────────────────────────
uint32_t off_thread_t_tro              = 0;
uint32_t off_thread_ro_tro_proc        = 0;
uint32_t off_thread_ro_tro_task        = 0;
uint32_t off_thread_machine_upcb       = 0;
uint32_t off_thread_machine_contextdata = 0;
uint32_t off_thread_ctid               = 0;
uint32_t off_thread_options            = 0;
uint32_t off_thread_mutex_lck_mtx_data = 0;
uint32_t off_thread_machine_kstackptr  = 0;
uint32_t off_thread_guard_exc_info_code = 0;
uint32_t off_thread_mach_exc_info_code = 0;
uint32_t off_thread_mach_exc_info_os_reason = 0;
uint32_t off_thread_mach_exc_info_exception_type = 0;
uint32_t off_thread_ast                = 0;
uint32_t off_thread_task_threads_next  = 0;
uint32_t off_thread_machine_jop_pid    = 0;
uint32_t off_thread_machine_rop_pid    = 0;
uint32_t off_task_itk_space            = 0;
uint32_t off_task_threads_next         = 0;
uint32_t off_task_task_exc_guard       = 0;
uint32_t off_task_map                  = 0;
uint32_t off_proc_p_list_le_next       = 0;
uint32_t off_proc_p_list_le_prev       = 0;
uint32_t off_proc_p_proc_ro            = 0;
uint32_t off_proc_p_pid                = 0;
uint32_t off_proc_p_fd                 = 0;
uint32_t off_proc_p_flag               = 0;
uint32_t off_proc_p_textvp             = 0;
uint32_t off_proc_p_name               = 0;
uint32_t off_proc_ro_pr_task           = 0;
uint32_t off_proc_ro_p_ucred           = 0;
uint32_t off_ucred_cr_label            = 0;
uint32_t off_label_l_perpolicy_amfi    = 0;
uint32_t off_label_l_perpolicy_sandbox = 0;
uint32_t off_ipc_space_is_table        = 0;
uint32_t off_ipc_entry_ie_object       = 0;
uint32_t off_ipc_port_ip_kobject       = 0;
uint32_t sizeof_ipc_entry              = 0;
uint32_t off_vm_map_hdr                = 0;
uint32_t off_vm_map_header_nentries    = 0;
uint32_t off_vm_map_entry_links_next   = 0;
uint32_t off_vm_map_entry_vme_object_or_delta = 0;
uint32_t off_vm_map_entry_vme_alias    = 0;
uint32_t off_vm_map_header_links_next  = 0;
uint32_t off_vm_object_vo_un1_vou_size = 0;
uint32_t off_vm_object_ref_count       = 0;
uint32_t off_vm_named_entry_backing_copy = 0;
uint32_t off_vm_named_entry_size       = 0;
uint32_t off_vnode_v_ncchildren_tqh_first = 0;
uint32_t off_vnode_v_nclinks_lh_first  = 0;
uint32_t off_vnode_v_parent            = 0;
uint32_t off_vnode_v_data              = 0;
uint32_t off_vnode_v_name              = 0;
uint32_t off_vnode_v_usecount          = 0;
uint32_t off_vnode_v_iocount           = 0;
uint32_t off_vnode_v_writecount        = 0;
uint32_t off_vnode_v_flag              = 0;
uint32_t off_vnode_v_mount             = 0;
uint32_t off_mount_mnt_flag            = 0;
uint32_t off_namecache_nc_vp           = 0;
uint32_t off_namecache_nc_child_tqe_next = 0;
uint32_t off_filedesc_fd_ofiles        = 0;
uint32_t off_filedesc_fd_cdir          = 0;
uint32_t off_fileproc_fp_glob          = 0;
uint32_t off_fileglob_fg_data          = 0;
uint32_t off_fileglob_fg_flag          = 0;
uint32_t off_inpcb_inp_list_le_next    = 0;
uint32_t off_inpcb_inp_pcbinfo         = 0;
uint32_t off_inpcb_inp_socket          = 0;
uint32_t off_inpcbinfo_ipi_zone        = 0;
uint32_t off_inpcb_inp_depend6_inp6_icmp6filt = 0;
uint32_t off_inpcb_inp_depend6_inp6_chksum = 0;
uint32_t off_socket_so_usecount        = 0;
uint32_t off_socket_so_proto           = 0;
uint32_t off_socket_so_background_thread = 0;
uint32_t off_arm_saved_state64_lr      = 0;
uint32_t off_arm_saved_state64_pc      = 0;
uint32_t off_arm_saved_state_uss_ss_64 = 0;
uint32_t off_arm_kernel_saved_state_sp = 0;
uint32_t off_kalloc_type_view_kt_zv_zv_name = 0;
uint32_t off_ttbr0_el1                 = 0;
uint32_t off_ttbr1_el1                 = 0;
uint32_t off_ppl_zone                  = 0;
uint32_t off_ppl_check                 = 0;
uint32_t off_kernel_base               = 0;

uint64_t dsfun_smr_base                = 0;
uint64_t dsfun_t1sz_boot               = 0;
uint64_t dsfun_VM_MIN_KERNEL_ADDRESS   = 0;
uint64_t dsfun_VM_MAX_KERNEL_ADDRESS   = 0;

// ── Инициализация: копируем rc_off_* → off_* ─────────────────────────────────
void dsfun_offsets_init(void) {
    rc_offsets_init();

    off_thread_t_tro                   = rc_off_thread_t_tro;
    off_thread_ro_tro_proc             = rc_off_thread_ro_tro_proc;
    off_thread_ro_tro_task             = rc_off_thread_ro_tro_task;
    off_thread_ctid                    = rc_off_thread_ctid;
    off_thread_options                 = rc_off_thread_options;
    off_thread_mutex_lck_mtx_data      = rc_off_thread_mutex_lck_mtx_data;
    off_thread_machine_kstackptr       = rc_off_thread_machine_kstackptr;
    off_thread_guard_exc_info_code     = rc_off_thread_guard_exc_info_code;
    off_thread_mach_exc_info_code      = rc_off_thread_mach_exc_info_code;
    off_thread_mach_exc_info_os_reason = rc_off_thread_mach_exc_info_os_reason;
    off_thread_mach_exc_info_exception_type = rc_off_thread_mach_exc_info_exception_type;
    off_thread_ast                     = rc_off_thread_ast;
    off_thread_task_threads_next       = rc_off_thread_task_threads_next;
    off_thread_machine_jop_pid         = rc_off_thread_machine_jop_pid;
    off_thread_machine_rop_pid         = rc_off_thread_machine_rop_pid;
    off_task_itk_space                 = rc_off_task_itk_space;
    off_task_threads_next              = rc_off_task_threads_next;
    off_task_task_exc_guard            = rc_off_task_task_exc_guard;
    off_task_map                       = rc_off_task_map;
    off_proc_p_proc_ro                 = rc_off_proc_p_proc_ro;
    off_proc_ro_p_ucred                = rc_off_proc_ro_p_ucred;
    off_proc_ro_pr_task                = rc_off_proc_ro_pr_task;
    off_ucred_cr_label                 = rc_off_ucred_cr_label;
    off_label_l_perpolicy_amfi         = rc_off_label_l_perpolicy_amfi;
    off_label_l_perpolicy_sandbox      = rc_off_label_l_perpolicy_sandbox;
    off_ipc_space_is_table             = rc_off_ipc_space_is_table;
    off_ipc_entry_ie_object            = rc_off_ipc_entry_ie_object;
    off_ipc_port_ip_kobject            = rc_off_ipc_port_ip_kobject;
    off_vm_map_hdr                     = rc_off_vm_map_hdr;
    off_vm_map_header_nentries         = rc_off_vm_map_header_nentries;
    off_vm_map_entry_links_next        = rc_off_vm_map_entry_links_next;
    off_vm_map_entry_vme_object_or_delta = rc_off_vm_map_entry_vme_object_or_delta;
    off_vm_map_entry_vme_alias         = rc_off_vm_map_entry_vme_alias;
    off_vm_map_header_links_next       = rc_off_vm_map_header_links_next;
    off_vm_object_vo_un1_vou_size      = rc_off_vm_object_vo_un1_vou_size;
    off_vm_object_ref_count            = rc_off_vm_object_ref_count;
    off_vm_named_entry_backing_copy    = rc_off_vm_named_entry_backing_copy;
    off_vm_named_entry_size            = rc_off_vm_named_entry_size;
    off_arm_kernel_saved_state_sp      = rc_off_arm_kernel_saved_state_sp;

    dsfun_smr_base = smr_base;
    dsfun_t1sz_boot = t1sz_boot;
    dsfun_VM_MIN_KERNEL_ADDRESS = 0xfffffff007000000ULL;
    dsfun_VM_MAX_KERNEL_ADDRESS = 0xfffffffffffffff0ULL;
}
