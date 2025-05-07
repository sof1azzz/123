#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "threads/vaddr.h"  // for is_user_vaddr
#include "threads/pte.h"    // For PTE flags PTE_P, PTE_W (and potentially PTE_U)
#include "lib/kernel/stdio.h"  // 包含 putbuf()
#include "threads/synch.h"  // lock
#include "userprog/pagedir.h"
#include "filesys/file.h"      
#include "filesys/filesys.h" 
//#include "lib/user/syscall.h"

static void syscall_handler(struct intr_frame *);
bool is_valid_user_addr(const void *uaddr, size_t size, bool check_writeable);


static struct lock filesys_global_lock;

void syscall_init(void) {
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&filesys_global_lock);
}

static void syscall_handler(struct intr_frame *f UNUSED) {
  uint32_t *args = ((uint32_t *)f->esp);

  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

   /* printf("System call number: %d\n", args[0]); */

  switch (args[0]) {
  case SYS_EXIT:  // SYS_EXIT = 1
    f->eax = args[1];
    printf("%s: exit(%d)\n", thread_current()->pcb->process_name, args[1]);
    process_exit();
    break;

  case SYS_PRACTICE:
    int arg = args[1];
    arg++;
    f->eax = arg;
    break;

  case SYS_WRITE: // SYS_WRITE = 9
    int fd = args[1];
    const char *user_buffer = (char *)args[2];
    int bytes_to_write = args[3];
    int bytes_written = -1;
    struct file *curr_file;

    if (fd <= 0 || fd >= MAX_OPEN_FILES) {
      printf("syscall_handler_SYS_WRITE: Invalid fd %d\n", fd);
      goto write_end;
    }

    if (!is_valid_user_addr(user_buffer, bytes_to_write, false)) {
      printf("syscall_handler_SYS_WRITE: Cannot write at fd: %d, start address: %x, size: %d\n",
        fd, (uint32_t)user_buffer, bytes_to_write);
      f->eax = -1; // 通常设置系统调用返回值为 -1 (虽然进程将终止)
      printf("%s: exit(-1)\n", thread_current()->name); // 打印消息
      process_exit(); // 调用内核的退出函数
      goto write_end;
    }

    if (fd == 1) {  // fd = stdout == 1
      putbuf(user_buffer, bytes_to_write); // 应该一定是成功的

      bytes_written = bytes_to_write;
      goto write_end; // 跳转到设置 f->eax 的地方
    }

    curr_file = thread_current()->pcb->fd_table[fd];

    if (curr_file == NULL) {
      printf("syscall_handler_SYS_WRITE: No such fd %d\n", fd);
      goto write_end;
    }

    lock_acquire(&filesys_global_lock);
    bytes_written = file_write(curr_file, user_buffer, bytes_to_write);
    lock_release(&filesys_global_lock);

  write_end:
    f->eax = bytes_written;
    break;

  default:
    break;
  }
}

/**
 * @brief 检查一个内存区域是否位于用户虚拟地址空间并且已映射（基本检查）。
 * * @param uaddr 用户空间起始虚拟地址。
 * @param size  要检查的区域大小（字节）。
 * @param check_writeable 如果为 true，则额外检查页面是否可写（对于 SYS_READ 等需要）。
 * 如果为 false，则仅检查可读性或存在性（对于 SYS_WRITE 等需要）。
 * @return 如果整个区域有效且满足可写性要求（如果检查的话），则返回 true；否则返回 false。
 */
bool is_valid_user_addr(const void *uaddr, size_t size, bool check_writeable) {
  if (size == 0) {
    return true;
  }

  const char *start_ptr = (const char *)uaddr;
  const char *end_ptr = start_ptr + size - 1; // 计算最后一个字节的地址

  if (!is_user_vaddr(start_ptr) || (uintptr_t)end_ptr < (uintptr_t)start_ptr
    || !is_user_vaddr(end_ptr)) {
    return false; // 起始地址无效或范围计算溢出
  }

  struct thread *t = thread_current();
  uint32_t *pd = t->pcb->pagedir; // 获取当前进程的页目录

  // 如果页目录无效，则任何地址都无效 (虽然对于活动线程这不太可能)
  if (pd == NULL) {
    return false;
  }

  // 计算范围所跨越的第一个和最后一个页面的起始地址
  void *current_page_start = pg_round_down(start_ptr);
  void *last_page_start = pg_round_down((const char *)start_ptr + size - 1);

  // 迭代检查范围内的每一个页面
  for (; current_page_start <= last_page_start; current_page_start = (char *)current_page_start + PGSIZE) {
    // a. 查找页表项 (PTE)
    //    lookup_page() 是 Pintos 中常用的函数，它查找给定虚拟地址对应的 PTE。
    //    第三个参数 'false' 表示如果页或页表不存在，不要创建它们。
    //    如果PDE或PTE不存在，或者PDE/PTE没有设置User位，它通常返回NULL。
    uint32_t *pte = lookup_page(pd, current_page_start, false);

    // b. 检查 PTE 是否有效（存在且用户可访问）以及 Present 位
    //    (lookup_page 返回 NULL 通常已包含了这些检查)
    if (pte == NULL || !(*pte & PTE_P)) {
      // 页面未映射到物理内存，或者页表项不允许用户访问
      return false;
    }

    // c. 如果需要检查可写权限
    if (check_writeable) {
      // 检查 PTE 中的 Writeable 位 (PTE_W)
      if (!(*pte & PTE_W)) {
        // 页面存在但不可写
        return false;
      }
    }
  }

  // 如果循环完成，说明范围内的所有页面都有效且满足权限要求
  return true;
}
