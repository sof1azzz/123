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
#include "devices/shutdown.h"
#include "lib/string.h"
#include "devices/input.h"
#include "threads/palloc.h"

static void syscall_handler(struct intr_frame *);
bool is_valid_user_addr(const void *uaddr, size_t size, bool check_writeable);


struct lock filesys_global_lock;

void syscall_init(void) {
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&filesys_global_lock);
}

// Helper function to terminate the current process with a given status
// Also sets f->eax for the syscall return value, though process won't see it.
static void terminate_process(int status, struct intr_frame *f) {
  if (f) { // f might be NULL if called from a place without intr_frame
    f->eax = status == -1 ? -1 : (uint32_t)status; // Convention for syscall error
  }
  if (thread_current()->pcb) { // Check if pcb exists
    thread_current()->pcb->exit_code = status;
    // Use pcb->process_name if available and set, otherwise thread_current()->name
    const char *name_to_print = thread_current()->pcb->process_name;
    printf("%s: exit(%d)\n", name_to_print, status);
  } else {
    // Fallback if PCB is not available (should not happen for user process exit)
    printf("%s: exit(%d)\n", thread_current()->name, status);
  }
  process_exit(); // This function should not return
}

static void syscall_handler(struct intr_frame *f UNUSED) {
  if (!is_valid_user_addr(f->esp, sizeof(uint32_t), false)) {
    terminate_process(-1, f); // f is valid here
    return;
  }
  uint32_t *args = ((uint32_t *)f->esp);

  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

   /* printf("System call number: %d\n", args[0]); */

  switch (args[0]) {
  case SYS_HALT:  // SYS_HALT = 0
    shutdown_power_off();
    break;

  case SYS_EXIT:  // SYS_EXIT = 1
    // Need to validate args[1] is on stack, typically 1 argument.
    if (!is_valid_user_addr(f->esp + 4, sizeof(int), false)) {
      terminate_process(-1, f);
      break;
    }

    int status = (int)args[1];
    // No f->eax setting here as terminate_process handles it implicitly by exiting.
    // terminate_process will also set pcb->exit_code and print message.
    terminate_process(status, NULL); // Pass NULL for f, as we don't need to set f->eax for exit
    break;

  case SYS_EXEC:  // SYS_EXEC = 2
  {
    // Validate pointer to arguments array and the first argument (char*)
    if (!is_valid_user_addr(f->esp + 4, sizeof(char *), false)) {
      terminate_process(-1, f); // Sets f->eax = -1
      break;
    }
    const char *cmd_line = (const char *)args[1];

    // 验证命令行参数
    if (cmd_line == NULL || !is_valid_user_addr(cmd_line, 1, false)) {
      terminate_process(-1, f);
      break;
    }

    // 安全地检查整个命令行参数 
    int i;    
    for (i = 0; ; i++) {
      if (!is_valid_user_addr(cmd_line + i, 1, false)) {
        terminate_process(-1, f);
        break;
      }
      if (cmd_line[i] == '\0') {
        break;
      }
      if (i >= 4096) {
        terminate_process(-1, f);
        break;
      }
    }

    char *fn_copy = NULL;
    fn_copy = palloc_get_page(0);
    if (fn_copy == NULL) {
      printf("SYSCALL EXEC: Failed to allocate fn_copy\n");
      terminate_process(-1, f);
      break;
    }
    strlcpy(fn_copy, cmd_line, PGSIZE);

    char *delimiters = " \t\n\r\f\v";
    char *token;
    char *saved_ptr;
    token = strtok_r(fn_copy, delimiters, &saved_ptr);
    if (token == NULL) {
      printf("SYSCALL EXEC: 你鸡巴传了个什么鬼东西?\n");
      terminate_process(-1, f);
      break;
    }

    struct file *file = filesys_open(token);
    if (file == NULL) {
      f->eax = -1;
      palloc_free_page(fn_copy);
      break;
    }
    file_close(file);
    palloc_free_page(fn_copy);

    f->eax = process_execute(cmd_line);
    break;
  }

  case SYS_WAIT:  // SYS_WAIT = 3
    // Validate pointer to arguments array and the first argument (pid_t)
    if (!is_valid_user_addr(f->esp + 4, sizeof(pid_t), false)) {
      terminate_process(-1, f);
      break;
    }
    pid_t pid_to_wait_for = (pid_t)args[1];
    f->eax = process_wait(pid_to_wait_for);
    break;
  case SYS_CREATE: // SYS_CREATE = 4
  {
    if (!is_valid_user_addr(f->esp + 4, sizeof(char *), false) ||
      !is_valid_user_addr(f->esp + 8, sizeof(unsigned), false)) {
      terminate_process(-1, f);
      break;
    }

    const char *file_name = (const char *)args[1];

    // 验证文件名字符串
    if (file_name == NULL || !is_valid_user_addr(file_name, 1, false)) {
      terminate_process(-1, f);
      break;
    }

    // 安全地检查整个文件名
    int i;
    for (i = 0; ; i++) {
      if (!is_valid_user_addr(file_name + i, 1, false)) {
        terminate_process(-1, f);
        break;
      }
      if (file_name[i] == '\0') {
        break;
      }
      // 防止无限循环
      if (i >= 4096) {
        terminate_process(-1, f);
        break;
      }
    }

    // 获取文件大小参数
    unsigned initial_size = (unsigned)args[2];
    // 获取文件系统锁，确保文件操作的原子性
    lock_acquire(&filesys_global_lock);
    // 调用文件系统的create函数创建文件
    bool success = filesys_create(file_name, initial_size);
    // 释放文件系统锁
    lock_release(&filesys_global_lock);
    // 设置系统调用返回值
    f->eax = success ? 1 : 0;
  }
  break;

  case SYS_REMOVE: // SYS_REMOVE = 5
  {
    if (!is_valid_user_addr(f->esp + 4, sizeof(char *), false)) {
      terminate_process(-1, f);
      break;
    }

    const char *file_name_remove = (const char *)args[1];

    // 验证文件名字符串
    if (file_name_remove == NULL || !is_valid_user_addr(file_name_remove, 1, false)) {
      terminate_process(-1, f);
      break;
    }

    // 安全地检查整个文件名
    int j;
    for (j = 0; ; j++) {
      if (!is_valid_user_addr(file_name_remove + j, 1, false)) {
        terminate_process(-1, f);
        break;
      }
      if (file_name_remove[j] == '\0') {
        break;
      }
      // 防止无限循环
      if (j >= 4096) {
        terminate_process(-1, f);
        break;
      }
    }

    lock_acquire(&filesys_global_lock);
    bool success_remove = filesys_remove(file_name_remove);
    lock_release(&filesys_global_lock);

    f->eax = success_remove ? 1 : 0;
  }
  break;

  case SYS_OPEN:   // SYS_OPEN = 6
  {
    if (!is_valid_user_addr(f->esp + 4, sizeof(char *), false)) {
      terminate_process(-1, f);
      break;
    }

    const char *file_name_open = (const char *)args[1];

    // 验证文件名字符串
    if (file_name_open == NULL || !is_valid_user_addr(file_name_open, 1, false)) {
      terminate_process(-1, f);
      break;
    }

    // 安全地检查整个文件名
    int k;
    for (k = 0; ; k++) {
      if (!is_valid_user_addr(file_name_open + k, 1, false)) {
        terminate_process(-1, f);
        break;
      }
      if (file_name_open[k] == '\0') {
        break;
      }
      // 防止无限循环
      if (k >= 4096) {
        terminate_process(-1, f);
        break;
      }
    }

    lock_acquire(&filesys_global_lock);
    struct file *file = filesys_open(file_name_open);


    if (file == NULL) {
      f->eax = -1;
      lock_release(&filesys_global_lock);
      break;
    }

    //lock_acquire(&thread_current()->pcb->process_lock);
    // 查找未使用的文件描述符
    int fd = 2; // 从2开始，0和1分别是标准输入和输出
    while (fd < MAX_OPEN_FILES && thread_current()->pcb->fd_table[fd] != NULL) {
      fd++;
    }

    if (fd >= MAX_OPEN_FILES) {
      // 如果文件描述符表已满，关闭文件并返回错误
      file_close(file);
      lock_release(&filesys_global_lock);
      f->eax = -1;
    } else {
      // 分配文件描述符
      thread_current()->pcb->fd_table[fd] = file;
      f->eax = fd;
      lock_release(&filesys_global_lock);
      thread_current()->pcb->next_fd = fd + 1;
    }
  }
  break;

  case SYS_FILESIZE: // SYS_FILESIZE = 7
  {
    // 验证文件描述符参数
    if (!is_valid_user_addr(f->esp + 4, sizeof(int), false)) {
      terminate_process(-1, f);
      break;
    }

    int fd = args[1];

    // 检查文件描述符有效性
    if (fd < 0 || fd >= MAX_OPEN_FILES) {
      f->eax = -1;
      break;
    }

    struct file *file = thread_current()->pcb->fd_table[fd];

    // 检查文件是否存在
    if (file == NULL) {
      f->eax = -1;
      break;
    }

    // 获取文件大小
    lock_acquire(&filesys_global_lock);
    off_t size = file_length(file);
    lock_release(&filesys_global_lock);

    f->eax = size;
  }
  break;

  case SYS_READ: // SYS_READ = 8
  {
    // 验证参数
    if (!is_valid_user_addr(f->esp + 4, sizeof(int), false) ||
      !is_valid_user_addr(f->esp + 8, sizeof(void *), false) ||
      !is_valid_user_addr(f->esp + 12, sizeof(unsigned), false)) {
      terminate_process(-1, f);
      break;
    }

    int fd = args[1];
    void *buffer = (void *)args[2];
    unsigned size = args[3];

    // 验证缓冲区
    if (!is_valid_user_addr(buffer, size, true)) {
      terminate_process(-1, f);
      break;
    }

    // 检查文件描述符有效性
    if (fd < 0 || fd >= MAX_OPEN_FILES) {
      f->eax = -1;
      break;
    }

    // 处理不同的文件描述符
    int bytes_read = 0;

    if (fd == 0) {
      // 标准输入
      for (unsigned i = 0; i < size; i++) {
        uint8_t c = input_getc();
        *((uint8_t *)buffer + i) = c;
        bytes_read++;

        // 如果读到EOF或换行符，可以选择停止读取
        if (c == '\0' || c == '\n') {
          break;
        }
      }
    } else {
      // 普通文件
      struct file *file = thread_current()->pcb->fd_table[fd];

      if (file == NULL) {
        f->eax = -1;
        break;
      }

      lock_acquire(&filesys_global_lock);
      bytes_read = file_read(file, buffer, size);
      lock_release(&filesys_global_lock);
    }

    f->eax = bytes_read;
  }
  break;

  case SYS_WRITE: // SYS_WRITE = 9
    if (!is_valid_user_addr(f->esp + 4, sizeof(int), false) ||
      !is_valid_user_addr(f->esp + 8, sizeof(char *), false) ||
      !is_valid_user_addr(f->esp + 12, sizeof(int), false)) {
      terminate_process(-1, f);
      break;
    }

    int fd = args[1];
    const char *user_buffer = (char *)args[2];
    int bytes_to_write = args[3];
    int bytes_written = -1;
    struct file *curr_file;

    // 验证文件描述符
    if (fd < 0 || fd >= MAX_OPEN_FILES) {
      f->eax = -1;
      break;
    }

    // 验证用户缓冲区
    if (!is_valid_user_addr(user_buffer, bytes_to_write, false)) {
      terminate_process(-1, f);
      break;
    }

    // 标准输出处理
    if (fd == 1) {  // fd = stdout == 1
      putbuf(user_buffer, bytes_to_write);
      bytes_written = bytes_to_write;
    } else {
      // 获取文件
      curr_file = thread_current()->pcb->fd_table[fd];

      if (curr_file == NULL) {
        f->eax = -1;
        break;
      }

      // 写入文件
      lock_acquire(&filesys_global_lock);
      bytes_written = file_write(curr_file, user_buffer, bytes_to_write);
      lock_release(&filesys_global_lock);
    }

    f->eax = bytes_written;
    break;

  case SYS_SEEK: // SYS_SEEK = 10
  {
    // 验证参数
    if (!is_valid_user_addr(f->esp + 4, sizeof(int), false) ||
      !is_valid_user_addr(f->esp + 8, sizeof(unsigned), false)) {
      terminate_process(-1, f);
      break;
    }

    int fd = args[1];
    unsigned position = args[2];

    // 检查文件描述符有效性
    if (fd < 2 || fd >= MAX_OPEN_FILES) { // fd 0和1是标准输入输出，不能seek
      break; // seek对无效fd静默失败，不返回错误
    }

    struct file *file = thread_current()->pcb->fd_table[fd];

    // 文件不存在则静默失败
    if (file == NULL) {
      break;
    }

    // 设置文件位置
    lock_acquire(&filesys_global_lock);
    file_seek(file, position);
    lock_release(&filesys_global_lock);

    // seek没有返回值
  }
  break;

  case SYS_TELL: // SYS_TELL = 11
  {
    // 验证参数
    if (!is_valid_user_addr(f->esp + 4, sizeof(int), false)) {
      terminate_process(-1, f);
      break;
    }

    int fd = args[1];

    // 检查文件描述符有效性
    if (fd < 2 || fd >= MAX_OPEN_FILES) { // fd 0和1是标准输入输出，不能tell
      f->eax = 0; // 对于无效fd，返回0
      break;
    }

    struct file *file = thread_current()->pcb->fd_table[fd];

    // 文件不存在则返回0
    if (file == NULL) {
      f->eax = 0;
      break;
    }

    // 获取当前文件位置
    lock_acquire(&filesys_global_lock);
    off_t position = file_tell(file);
    lock_release(&filesys_global_lock);

    f->eax = position;
  }
  break;

  case SYS_CLOSE: // SYS_CLOSE = 12
  {
    // 验证参数
    if (!is_valid_user_addr(f->esp + 4, sizeof(int), false)) {
      terminate_process(-1, f);
      break;
    }

    int fd = args[1];

    // 检查文件描述符有效性
    if (fd < 2 || fd >= MAX_OPEN_FILES) { // fd 0和1是标准输入输出，不能关闭
      break; // close对无效fd静默失败
    }

    struct file *file = thread_current()->pcb->fd_table[fd];

    // 文件不存在则静默失败
    if (file == NULL) {
      break;
    }

    // 关闭文件
    lock_acquire(&filesys_global_lock);
    file_close(file);
    lock_release(&filesys_global_lock);

    // 清除文件描述符表中的条目
    thread_current()->pcb->fd_table[fd] = NULL;

    // close没有返回值
  }
  break;

  case SYS_PRACTICE:  // SYS_PRACTICE = 13
    int arg = args[1];
    arg++;
    f->eax = arg;
    break;

  case SYS_FORK:  // SYS_FORK = 32
    const char *thread_name = (const char *)args[1];
    // 调用 process_fork 并传递中断帧
    f->eax = process_fork(thread_name, f);
    break;

  default:
    printf("Unknown system call number: %d\n", args[0]);
    f->eax = -1; // Standard error return for unknown syscall
    terminate_process(-1, NULL); // Terminate the process for an invalid syscall
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
    if (current_page_start == NULL) { // Disallow access to page 0
      return false;
    }
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
