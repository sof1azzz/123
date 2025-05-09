#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "lib/string.h"

//static struct semaphore temporary;
static thread_func start_process NO_RETURN;
static thread_func start_pthread NO_RETURN;
static bool load(const char *file_name, void (**eip)(void), void **esp);
bool setup_thread(void (**eip)(void), void **esp);

static struct process *get_process_by_pid(pid_t pid);

// 全局进程列表，包含系统中所有的 struct process
static struct list all_processes_list;
// 用于保护 all_processes_list 的锁
static struct lock all_processes_lock;

#define MAX_ARGS 128

// 遍历全局链表找对应pid的process，返回process指针
struct process *get_process_by_pid(pid_t pid) {
  struct process *found_pcb = NULL;
  struct list_elem *e;

  lock_acquire(&all_processes_lock);
  for (e = list_begin(&all_processes_list); e != list_end(&all_processes_list); e = list_next(e)) {
    struct process *p = list_entry(e, struct process, global_elem);
    if (p->pid == pid) {
      found_pcb = p;
      break;
    }
  }
  lock_release(&all_processes_lock);

  return found_pcb;
}

/* Initializes user programs in the system by ensuring the main
   thread has a minimal PCB so that it can execute and wait for
   the first user process. Any additions to the PCB should be also
   initialized here if main needs those members */
void userprog_init(void) {
  struct thread *t = thread_current();
  bool success;

  /* Allocate process control block
     It is imoprtant that this is a call to calloc and not malloc,
     so that t->pcb->pagedir is guaranteed to be NULL (the kernel's
     page directory) when t->pcb is assigned, because a timer interrupt
     can come at any time and activate our pagedir */
  t->pcb = calloc(sizeof(struct process), 1);
  success = t->pcb != NULL;

  /* Kill the kernel if we did not succeed */
  ASSERT(success);

  struct process *curr_pcb = t->pcb;
  strlcpy(curr_pcb->process_name, t->name, sizeof(curr_pcb->process_name));
  curr_pcb->main_thread = t;
  curr_pcb->next_fd = 3;
  curr_pcb->pid = t->tid;

  list_init(&curr_pcb->children_list);
  lock_init(&curr_pcb->process_lock);

  // 全局process链表
  list_init(&all_processes_list);
  lock_init(&all_processes_lock);

  // 将主内核线程/初始进程的PCB也加入到全局列表中
  // (假设 t->pcb 已经被分配和部分初始化，包括 pid)
  struct process *initial_pcb = thread_current()->pcb;
  if (initial_pcb != NULL) { // 确保 t->pcb 已经设置
    // initial_pcb->pid = thread_current()->tid; // 确保PID已设置
    lock_acquire(&all_processes_lock);
    list_push_back(&all_processes_list, &initial_pcb->global_elem);
    lock_release(&all_processes_lock);
  }
}

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   process id, or TID_ERROR if the thread cannot be created. */
pid_t process_execute(const char *file_name_with_args) {
  char *fn_copy = NULL;    // 内核空间的参数副本，传递给子进程
  char *exe_name = NULL;   // 用于 strtok_r 分词的缓冲区，提取可执行文件名
  char *token = NULL;      // strtok_r 返回的第一个token（可执行文件名）
  char *save_ptr = NULL;   // strtok_r 使用的上下文指针
  tid_t tid = TID_ERROR;   // 新创建线程的TID，如果成功，则为子进程的PID
  struct load_helper aux;  // 用于父子进程间同步和传递参数的辅助结构
  pid_t result_pid = TID_ERROR;

  /* 1. 复制命令行参数到内核空间 (fn_copy) */
  // fn_copy 会传递给子进程，子进程加载成功后应由子进程释放。
  fn_copy = palloc_get_page(0);
  if (fn_copy == NULL) {
    printf("process_execute: fn_copy palloc_get_page failed\n");
    return TID_ERROR; // 内存分配失败
  }
  strlcpy(fn_copy, file_name_with_args, PGSIZE);
  aux.file_name_with_args = fn_copy;

  /* 2. 准备可执行文件名 (exe_name) 用于 thread_create */
  // exe_name 是父进程的临时缓冲区，用完后由父进程释放。
  exe_name = palloc_get_page(0);
  if (exe_name == NULL) {
    printf("process_execute: exe_name palloc_get_page failed\n");
    palloc_free_page(fn_copy); // 清理已分配的 fn_copy
    return TID_ERROR; // 内存分配失败
  }
  // 从 fn_copy (已经是内核安全拷贝) 复制到 exe_name 以便分词
  strlcpy(exe_name, fn_copy, PGSIZE);

  token = strtok_r(exe_name, " ", &save_ptr);
  if (token == NULL) {
    // 如果 file_name_with_args 是空字符串或只包含空格
    printf("process_execute: No executable name in '%s'\n", file_name_with_args);
    palloc_free_page(fn_copy);
    palloc_free_page(exe_name);
    return TID_ERROR;
  }

  sema_init(&aux.child_start_sema, 0);  // 新增：初始化子进程启动信号量

  /* 3. 初始化用于同步的信号量和加载成功标志 */
  sema_init(&aux.wait_sema, 0);
  aux.load_success = false; // 子进程 (start_process) 会在加载成功后将其设为 true
  aux.child_pid = TID_ERROR;  // 先设置一下
  aux.parent_pcb = thread_current()->pcb; // <--- 新增：设置父进程的PCB

  /* 4. 创建新线程以启动子进程 */
  // token (可执行文件名) 作为新线程的名称
  tid = thread_create(token, PRI_DEFAULT, start_process, &aux);

  if (tid == TID_ERROR) {
    // 线程创建失败，子进程未启动。父进程清理所有已分配资源。
    printf("process_execute: thread_create failed for '%s'\n", token);
    palloc_free_page(fn_copy);
    palloc_free_page(exe_name); // exe_name 是父进程的缓冲区
    return TID_ERROR;
  }

  /* 5. 等待子进程尝试加载可执行文件 */
  sema_down(&aux.wait_sema);

  /* 6. 检查子进程是否成功加载程序 */
  if (aux.load_success) {
    // 子进程加载成功。
    // 此时，fn_copy (aux.file_name_with_args) 应该已由子进程 (start_process)
    // 在将其内容复制到用户栈后释放。这是父子进程间的约定。

    // 父进程负责清理它自己的临时缓冲区 exe_name。
    palloc_free_page(exe_name);

    // TODO (非常重要): 在这里将子进程 (tid) 添加到当前进程的 children_list。
    // 这是实现 process_wait 的关键步骤。
    // 例如:
    struct process *current_parent_pcb = thread_current()->pcb;
    struct child_status *child_tracker = malloc(sizeof(struct child_status));

    if (child_tracker != NULL) {
      child_tracker->child_pid = aux.child_pid; // 使用子进程通过aux传递回来的PID
      child_tracker->has_exited = false;
      child_tracker->parent_has_waited = false;
      child_tracker->exit_code = -1; // 初始值，表示尚未退出或未知
      sema_init(&child_tracker->wait_sema, 0); // 父进程在此等待该特定子进程退出

      lock_acquire(&current_parent_pcb->process_lock);
      list_push_back(&current_parent_pcb->children_list, &child_tracker->elem);
      lock_release(&current_parent_pcb->process_lock);



      result_pid = aux.child_pid; // 设置函数返回值为子进程的PID
    } else {
      // 为 child_tracker 分配内存失败。这是一个严重错误。
      // 子进程已经在运行 (因为 aux.load_success == true)，但父进程无法为其建立追踪结构以供 wait() 使用。
      printf("process_execute: Malloc failed for child_status (child PID %d). Parent cannot track for wait().\n", (int)aux.child_pid);
      // printf 的参数用 aux.child_pid 更准确，因为这是子进程自己上报的PID。
      // 你之前的代码用了 tid，tid 是线程创建的返回值，通常它们相同，但 aux.child_pid 更直接。

      // 通知上层调用者，尽管子进程可能在运行，但 process_execute 未能完全成功建立父子追踪关系。
      result_pid = TID_ERROR;

      // 关于已分配资源的清理：
      // 1. exe_name: 已经在 if (aux.load_success) 块的开头，child_tracker 分配尝试之前被父进程释放了。
      // 2. fn_copy: 因为 aux.load_success == true，根据约定，fn_copy 应该已经被子进程 (start_process) 释放了。
      // 所以在这里，父进程没有额外的内核页面需要释放。
    }
    sema_up(&aux.child_start_sema); // 新增
  } else {
    // 子进程加载失败。子线程应该已经或即将退出。
    // 根据约定，如果加载失败，start_process 不会释放 fn_copy。
    // 父进程需要清理 fn_copy 和 exe_name。
    printf("process_execute: child process (tid %d) failed to load '%s'.\n", tid, aux.file_name_with_args);
    palloc_free_page(fn_copy);
    palloc_free_page(exe_name);
  }
  return result_pid;
}

/* A thread function that loads a user process and starts it
   running. */
   // 参数是   ----->    struct load_helper aux;
  // 还没有进行token， token在 当前 281 行 函数 load里面进行
static void start_process(void *arg) {
  struct load_helper *aux = (struct load_helper *)arg;
  char *file_name_with_args = aux->file_name_with_args;
  struct thread *t = thread_current();
  struct intr_frame if_;
  bool success = false; // 默认失败
  struct process *new_pcb = NULL;

  new_pcb = malloc(sizeof(struct process));
  if (new_pcb == NULL) {
    printf("start_process: PCB malloc failed\n");
    // aux->load_success 默认为 false (或在父进程中初始化为 false)
    // 若要显式设置: aux->load_success = false;
    // aux->child_pid 保持为 TID_ERROR (或在父进程中初始化)
    sema_up(&aux->wait_sema); // 必须通知父进程
    thread_exit();
  }

  // 初始化PCB字段 (pagedir 必须在 t->pcb 赋值前设为 NULL)
  new_pcb->pagedir = NULL;
  t->pcb = new_pcb; // 将线程链接到PCB

  new_pcb->main_thread = t;
  strlcpy(new_pcb->process_name, t->name, sizeof(new_pcb->process_name));
  list_init(&new_pcb->children_list);
  lock_init(&new_pcb->process_lock); // 修正：初始化正确的锁
  new_pcb->pid = t->tid;
  new_pcb->parent_pcb = aux->parent_pcb; // 从aux获取父PCB
  new_pcb->executable_file = NULL; // 若使用malloc，需手动初始化
  new_pcb->is_exited = false;
  new_pcb->exit_code = -1;
  new_pcb->next_fd = 3; // 假设0和1将被用于stdin/stdout, assume 2 == stderr

  // -------- 新增：初始化文件描述符表 --------
  for (int i = 0; i < MAX_OPEN_FILES; i++) {
    new_pcb->fd_table[i] = NULL;
  }

  // 将PID传递给父进程
  aux->child_pid = new_pcb->pid;

  // 加入全局进程列表
  lock_acquire(&all_processes_lock);
  list_push_back(&all_processes_list, &new_pcb->global_elem);
  lock_release(&all_processes_lock);

  /* 2. 初始化中断帧并加载可执行文件 */
  memset(&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;

  success = load(file_name_with_args, &if_.eip, &if_.esp);

  /* 3. 处理加载结果 */
  if (success) {
    aux->load_success = true;
    // 加载成功，子进程负责释放 fn_copy (file_name_with_args)
    sema_up(&aux->wait_sema);       // 通知父进程加载成功
    sema_down(&aux->child_start_sema); // 新增：等待父进程完成添加操作
    palloc_free_page(file_name_with_args);
  } else { // 加载失败
    aux->load_success = false;
    // PCB已分配但加载失败，需要清理PCB
    t->pcb = NULL; // 断开线程与PCB的链接

    lock_acquire(&all_processes_lock);
    list_remove(&new_pcb->global_elem); // 从全局列表移除
    lock_release(&all_processes_lock);

    free(new_pcb); // 释放PCB内存
    new_pcb = NULL;
    // file_name_with_args 不在此处释放，由父进程处理
    /* 4. 通知父进程，如果失败则退出线程 */
    sema_up(&aux->wait_sema);

    thread_exit();
  }

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */

  asm volatile("movl %0, %%esp; jmp intr_exit" : : "g"(&if_) : "memory");
  NOT_REACHED();
}

/* Waits for process with PID child_pid to die and returns its exit status.
   If it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If child_pid is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given PID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int process_wait(pid_t child_pid) {
  struct thread *current_thread = thread_current();
  struct process *parent_pcb = current_thread->pcb;
  struct child_status *cs = NULL;
  struct list_elem *e;
  bool child_found = false;
  int exit_status = -1; // 默认返回 -1

  if (parent_pcb == NULL) {
    return -1; // 父进程没有PCB，无法追踪子进程
  }

  lock_acquire(&parent_pcb->process_lock);

  for (e = list_begin(&parent_pcb->children_list);
    e != list_end(&parent_pcb->children_list);
    e = list_next(e)) {
    struct child_status *temp_cs = list_entry(e, struct child_status, elem);
    if (temp_cs->child_pid == child_pid) {
      cs = temp_cs;
      child_found = true;
      break;
    }
  }

  // 2. 处理找不到子进程或已等待过的情况
  if (!child_found || cs == NULL) {
    // 子进程ID无效，或不是当前进程的子进程
    lock_release(&parent_pcb->process_lock);
    return -1;
  }

  if (cs->parent_has_waited) {
    // 已经成功等待过此子进程
    lock_release(&parent_pcb->process_lock);
    return -1;
  }
  // 3. 如果子进程尚未退出，则等待
      //    子进程的 process_exit 会设置 cs->has_exited 和 cs->exit_code，
      //    并对 cs->wait_sema 执行 V 操作。
  if (!cs->has_exited) {
    // 创建本地副本
    /*
    2025.5.10
    我操死你的妈妈
    为什么为什么为什么？
    为什么这边保留一个指针struct semaphore *wait_sema = &cs->wait_sema;就可以了？
    花费了这么多小时
    以后在锁 release和acquire之间我都会保留副本的
    我操你妈
    */
    struct semaphore *wait_sema = &cs->wait_sema;
    lock_release(&parent_pcb->process_lock);
    sema_down(wait_sema);

    // 释放锁后，cs可能已被子进程释放，需要重新查找
    lock_acquire(&parent_pcb->process_lock);
    bool still_exists = false;
    for (e = list_begin(&parent_pcb->children_list);
      e != list_end(&parent_pcb->children_list);
      e = list_next(e)) {
      struct child_status *temp_cs = list_entry(e, struct child_status, elem);
      if (temp_cs->child_pid == child_pid) {
        cs = temp_cs;
        still_exists = true;
        break;
      }
    }

    if (!still_exists) {
      lock_release(&parent_pcb->process_lock);
      return -1;
    }
  }
  // 此刻，无论之前是否等待，子进程肯定已经退出了 (cs->has_exited 应该为 true)

  // 4. 获取退出状态
  exit_status = cs->exit_code;

  // 5. 标记为已等待，并从列表中移除，释放资源
  cs->parent_has_waited = true;
  list_remove(&cs->elem); // 从 children_list 中移除

  lock_release(&parent_pcb->process_lock); // 在 free 之前释放锁

  free(cs); // 释放 child_status 结构体

  return exit_status;
}

/* Free the current process's resources. */
void process_exit(void) {
  struct thread *cur = thread_current();
  struct process *pcb = cur->pcb;

  if (pcb == NULL) {
    thread_exit(); // 直接退出线程
    NOT_REACHED();
  }

  /* If this thread does not have a PCB, don't worry */
  if (cur->pcb == NULL) {
    thread_exit();
    NOT_REACHED();
  }

  if (pcb->parent_pcb != NULL) {
    struct lock *process_lock = &pcb->parent_pcb->process_lock;
    lock_acquire(process_lock);

    struct list_elem *e;
    struct child_status *cs = NULL;
    for (e = list_begin(&pcb->parent_pcb->children_list);
      e != list_end(&pcb->parent_pcb->children_list);
      e = list_next(e)) {
      cs = list_entry(e, struct child_status, elem);
      if (cs->child_pid == pcb->pid) {
        cs->has_exited = true;
        cs->exit_code = pcb->exit_code;
        sema_up(&cs->wait_sema); // 唤醒正在等待此子进程的父进程
        break;
      }
    }
    lock_release(process_lock);
  }

  for (int fd = 0; fd < MAX_OPEN_FILES; fd++) { // 通常FD 0, 1不是文件表中的实际文件
    if (pcb->fd_table[fd] != NULL) {
      file_close(pcb->fd_table[fd]);
      pcb->fd_table[fd] = NULL;
    }
  }

  // 5. 关闭可执行文件 (如果已打开)
  if (pcb->executable_file != NULL) {
    file_allow_write(pcb->executable_file); // 配对 file_deny_write
    file_close(pcb->executable_file);
    pcb->executable_file = NULL;
  }

  // 6. 从全局进程列表中移除 (关键步骤，必须在 free(pcb) 之前)
  lock_acquire(&all_processes_lock);
  // 检查元素是否仍在链表中，以增加稳健性，尽管 list_remove 内部也会断言
  list_remove(&pcb->global_elem);

  lock_release(&all_processes_lock);
  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  uint32_t *pd = pcb->pagedir;
  if (pd != NULL) {
    /* Correct ordering here is crucial.  We must set
         cur->pcb->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
         // 正确的顺序至关重要，如您原代码注释所述
    pcb->pagedir = NULL;        // 先清除PCB中的页目录指针
    pagedir_activate(NULL);     // 激活内核页目录
    pagedir_destroy(pd);        // 然后销毁进程的页目录
  }

  /* Free the PCB of this process and kill this thread
     Avoid race where PCB is freed before t->pcb is set to NULL
     If this happens, then an unfortuantely timed timer interrupt
     can try to activate the pagedir, but it is now freed memory */
  cur->pcb = NULL;          // 在释放PCB之前，将线程的pcb指针置空
  free(pcb);                // 释放PCB本身

  // 9. 终止当前内核线程
  thread_exit(); // 此函数不会返回
  NOT_REACHED();
}

/* Sets up the CPU for running user code in the current
   thread. This function is called on every context switch. */
void process_activate(void) {
  struct thread *t = thread_current();

  /* Activate thread's page tables. */
  if (t->pcb != NULL && t->pcb->pagedir != NULL)
    pagedir_activate(t->pcb->pagedir);
  else
    pagedir_activate(NULL);

  /* Set thread's kernel stack for use in processing interrupts.
     This does nothing if this is not a user process. */
  tss_update();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

   /* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32 /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32 /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32 /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16 /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr {
  unsigned char e_ident[16];
  Elf32_Half e_type;
  Elf32_Half e_machine;
  Elf32_Word e_version;
  Elf32_Addr e_entry;
  Elf32_Off e_phoff;
  Elf32_Off e_shoff;
  Elf32_Word e_flags;
  Elf32_Half e_ehsize;
  Elf32_Half e_phentsize;
  Elf32_Half e_phnum;
  Elf32_Half e_shentsize;
  Elf32_Half e_shnum;
  Elf32_Half e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr {
  Elf32_Word p_type;
  Elf32_Off p_offset;
  Elf32_Addr p_vaddr;
  Elf32_Addr p_paddr;
  Elf32_Word p_filesz;
  Elf32_Word p_memsz;
  Elf32_Word p_flags;
  Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL 0           /* Ignore. */
#define PT_LOAD 1           /* Loadable segment. */
#define PT_DYNAMIC 2        /* Dynamic linking info. */
#define PT_INTERP 3         /* Name of dynamic loader. */
#define PT_NOTE 4           /* Auxiliary info. */
#define PT_SHLIB 5          /* Reserved. */
#define PT_PHDR 6           /* Program header table. */
#define PT_STACK 0x6474e551 /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

static bool setup_stack(void **esp);
static bool validate_segment(const struct Elf32_Phdr *, struct file *);
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage, uint32_t read_bytes,
  uint32_t zero_bytes, bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
   // file_name 参数是   ----->    包含所有argv： file_name(argv[0]), argv[1], argv[2]......
     // 还没有进行token， token在 当前 281 行 函数 load里面进行
bool load(const char *file_name, void (**eip)(void), void **esp) {
  struct thread *t = thread_current();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  char *saved_ptr;
  char *token;
  int argc = 0;
  char *ELF_name;
  const char *delimiters = " \t\n\r\f\v";
  char *argv[MAX_ARGS];
  int argv_bytes_len = 0;
  int argv_bytes_align_needed = 0;
  argv[MAX_ARGS - 1] = NULL;

  char *fn_copy = NULL;
  fn_copy = palloc_get_page(0);
  if (fn_copy == NULL) {
    printf("load: Failed to allocate fn_copy\n");
    goto done;
  }
  strlcpy(fn_copy, file_name, PGSIZE);

  token = strtok_r(fn_copy, delimiters, &saved_ptr);
  if (token == NULL) {
    printf("load: 你鸡巴传了个什么鬼东西?\n");
    goto done;
  }

  ELF_name = token;

  // 补救措施。 因为在execute_process里面我们没有正确的把argv[0]赋值给process_name
  strlcpy(thread_current()->pcb->process_name, ELF_name, sizeof(thread_current()->pcb->process_name));

  argv_bytes_len += strlen(token) + 1;
  argv[0] = ELF_name;
  argc++;

  // strtok_r 第一个参数是 NULL !
  while ((token = strtok_r(NULL, delimiters, &saved_ptr)) != NULL
    && argc < MAX_ARGS - 1) {
    argv[argc] = token;
    // 记得加'\0'
    argv_bytes_len += strlen(token) + 1;
    argc++;
  }

  // 这边边界大小 目前不是很确定   一堆参数，下面有注释
  int metadata_size = (argc + 1) * sizeof(char *) +  // argv[0]...argv[argc-1] 和 argv[argc]=NULL
    sizeof(char **) +             // char **argv (指向 argv[0] 的指针)
    sizeof(int) +                // int argc
    sizeof(void *);               // fake return address
  if (argv_bytes_len + metadata_size > PGSIZE) {
    printf("load: Too many argv\n");
    goto done;
  }

  argv[argc] = NULL;

  /* Allocate and activate page directory. */
  t->pcb->pagedir = pagedir_create();
  if (t->pcb->pagedir == NULL)
    goto done;
  process_activate();

  /* Open executable file. */
  file = filesys_open(ELF_name);
  if (file == NULL) {
    printf("load: %s: open failed\n", ELF_name);
    goto done;
  }

  t->pcb->executable_file = file;     // pcb里面的

  /* Read and verify executable header. */
  if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr ||
    memcmp(ehdr.e_ident, "\177ELF\1\1\1", 7) || ehdr.e_type != 2 || ehdr.e_machine != 3 ||
    ehdr.e_version != 1 || ehdr.e_phentsize != sizeof(struct Elf32_Phdr) || ehdr.e_phnum > 1024) {
    printf("load: %s: error loading executable\n", ELF_name);
    goto done;
  }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) {
    struct Elf32_Phdr phdr;

    if (file_ofs < 0 || file_ofs > file_length(file))
      goto done;
    file_seek(file, file_ofs);

    if (file_read(file, &phdr, sizeof phdr) != sizeof phdr)
      goto done;
    file_ofs += sizeof phdr;
    switch (phdr.p_type) {
    case PT_NULL:
    case PT_NOTE:
    case PT_PHDR:
    case PT_STACK:
    default:
      /* Ignore this segment. */
      break;
    case PT_DYNAMIC:
    case PT_INTERP:
    case PT_SHLIB:
      goto done;
    case PT_LOAD:
      if (validate_segment(&phdr, file)) {
        bool writable = (phdr.p_flags & PF_W) != 0;
        uint32_t file_page = phdr.p_offset & ~PGMASK;
        uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
        uint32_t page_offset = phdr.p_vaddr & PGMASK;
        uint32_t read_bytes, zero_bytes;
        if (phdr.p_filesz > 0) {
          /* Normal segment.
                   Read initial part from disk and zero the rest. */
          read_bytes = page_offset + phdr.p_filesz;
          zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) - read_bytes);
        } else {
          /* Entirely zero.
                   Don't read anything from disk. */
          read_bytes = 0;
          zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
        }
        if (!load_segment(file, file_page, (void *)mem_page, read_bytes, zero_bytes, writable))
          goto done;
      } else
        goto done;
      break;
    }
  }

  /* Set up stack. */
  if (!setup_stack(esp))
    goto done;

  char *argv_start_addr[MAX_ARGS];
  char *curr_esp_addr = *esp;
  int k_loop;

  for (k_loop = argc - 1; k_loop >= 0; k_loop--) {
    int curr_argv_len = strlen(argv[k_loop]) + 1;
    curr_esp_addr -= curr_argv_len;
    memcpy(curr_esp_addr, argv[k_loop], curr_argv_len);
    argv_start_addr[k_loop] = curr_esp_addr;
  }

  // 所有的argv，argc，还有虚拟return地址所需bytes
  // argv_bytes_len + 4 (argv[argc]为NULL) + 4 (argv) + 4 (argc)  + 
  // 4 * argc(每个argv[i])    不包含虚拟返回地址， 此时需要满足 16 对齐
  argv_bytes_align_needed = (16 - (argv_bytes_len + 4 + 4 + 4 + 4 * argc) % 16) % 16;
  for (k_loop = argv_bytes_align_needed; k_loop > 0; k_loop--) {
    curr_esp_addr--;
    *(uint8_t *)curr_esp_addr = 0; // 每个 0 只占 1 byte
  }

  // 设置 argv[argc] = NULL (4 bytes)
  curr_esp_addr -= sizeof(char *);
  *(char **)curr_esp_addr = 0;  // 这两个等价， 反正填一个 4 bytes 的 0 
  //*(uint32_t *)curr_esp_addr = (uint32_t)0;

  for (k_loop = argc - 1; k_loop >= 0; k_loop--) {
    curr_esp_addr -= sizeof(char *);
    *(char **)curr_esp_addr = argv_start_addr[k_loop];
  }

  // 压入 argv 
  char **main_argv_parameter_on_stack = (char **)curr_esp_addr;
  curr_esp_addr -= sizeof(char **);
  *((char ***)curr_esp_addr) = main_argv_parameter_on_stack;

  // argc
  curr_esp_addr -= sizeof(int);
  *((int *)curr_esp_addr) = argc;

  // 虚假地址
  curr_esp_addr -= sizeof(void *);
  *((void **)curr_esp_addr) = NULL;

  *esp = curr_esp_addr;  // 改回来

  /* Start address. */
  *eip = (void (*)(void))ehdr.e_entry;

  success = true;

done:
  /* We arrive here whether the load is successful or not. */
  palloc_free_page(fn_copy);  // free

  if (success) {
    // 加载成功。t->pcb->executable_file 已被设置。
    //ASSERT(t->pcb->executable_file != NULL); // 断言文件已设置
    file_deny_write(t->pcb->executable_file); // 禁止写入可执行文件
    // 注意：不在此处关闭 t->pcb->executable_file，它将由 process_exit 关闭
  } else {
    // 加载失败。
    // 如果可执行文件曾被打开并记录在PCB中，则关闭它并清除PCB中的记录。
    if (t->pcb->executable_file != NULL) {
      file_allow_write(t->pcb->executable_file); // 在关闭前允许写入
      file_close(t->pcb->executable_file);
      t->pcb->executable_file = NULL;
    }
    // 如果 t->pcb->executable_file 为 NULL 但局部变量 file 曾被打开（例如在赋值给PCB前失败），
    // 这种可能性很小，因为您在打开后立即赋值了。
    // else if (file != NULL) { file_close(file); } // 通常不需要这一额外分支了
  }
  return success;
}

/* load() helpers. */

static bool install_page(void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool validate_segment(const struct Elf32_Phdr *phdr, struct file *file) {
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off)file_length(file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr((void *)phdr->p_vaddr))
    return false;
  if (!is_user_vaddr((void *)(phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage, uint32_t read_bytes,
  uint32_t zero_bytes, bool writable) {
  ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT(pg_ofs(upage) == 0);
  ASSERT(ofs % PGSIZE == 0);

  file_seek(file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) {
    /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

    /* Get a page of memory. */
    uint8_t *kpage = palloc_get_page(PAL_USER);
    if (kpage == NULL)
      return false;

    /* Load this page. */
    if (file_read(file, kpage, page_read_bytes) != (int)page_read_bytes) {
      palloc_free_page(kpage);
      return false;
    }
    memset(kpage + page_read_bytes, 0, page_zero_bytes);

    /* Add the page to the process's address space. */
    if (!install_page(upage, kpage, writable)) {
      palloc_free_page(kpage);
      return false;
    }

    /* Advance. */
    read_bytes -= page_read_bytes;
    zero_bytes -= page_zero_bytes;
    upage += PGSIZE;
  }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool setup_stack(void **esp) {
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page(PAL_USER | PAL_ZERO);
  if (kpage != NULL) {
    success = install_page(((uint8_t *)PHYS_BASE) - PGSIZE, kpage, true);
    if (success)
      *esp = PHYS_BASE;
    else
      palloc_free_page(kpage);
  }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool install_page(void *upage, void *kpage, bool writable) {
  struct thread *t = thread_current();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page(t->pcb->pagedir, upage) == NULL &&
    pagedir_set_page(t->pcb->pagedir, upage, kpage, writable));
}

/* Returns true if t is the main thread of the process p */
bool is_main_thread(struct thread *t, struct process *p) { return p->main_thread == t; }

/* Gets the PID of a process */
pid_t get_pid(struct process *p) { return (pid_t)p->main_thread->tid; }

/* Creates a new stack for the thread and sets up its arguments.
   Stores the thread's entry point into *EIP and its initial stack
   pointer into *ESP. Handles all cleanup if unsuccessful. Returns
   true if successful, false otherwise.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. You may find it necessary to change the
   function signature. */
bool setup_thread(void (**eip)(void) UNUSED, void **esp UNUSED) { return false; }

/* Starts a new thread with a new user stack running SF, which takes
   TF and ARG as arguments on its user stack. This new thread may be
   scheduled (and may even exit) before pthread_execute () returns.
   Returns the new thread's TID or TID_ERROR if the thread cannot
   be created properly.

   This function will be implemented in Project 2: Multithreading and
   should be similar to process_execute (). For now, it does nothing.
   */
tid_t pthread_execute(stub_fun sf UNUSED, pthread_fun tf UNUSED, void *arg UNUSED) { return -1; }

/* A thread function that creates a new user thread and starts it
   running. Responsible for adding itself to the list of threads in
   the PCB.

   This function will be implemented in Project 2: Multithreading and
   should be similar to start_process (). For now, it does nothing. */
static void start_pthread(void *exec_ UNUSED) {}

/* Waits for thread with TID to die, if that thread was spawned
   in the same process and has not been waited on yet. Returns TID on
   success and returns TID_ERROR on failure immediately, without
   waiting.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
tid_t pthread_join(tid_t tid UNUSED) { return -1; }

/* Free the current thread's resources. Most resources will
   be freed on thread_exit(), so all we have to do is deallocate the
   thread's userspace stack. Wake any waiters on this thread.

   The main thread should not use this function. See
   pthread_exit_main() below.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
void pthread_exit(void) {}

/* Only to be used when the main thread explicitly calls pthread_exit.
   The main thread should wait on all threads in the process to
   terminate properly, before exiting itself. When it exits itself, it
   must terminate the process in addition to all necessary duties in
   pthread_exit.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
void pthread_exit_main(void) {}
