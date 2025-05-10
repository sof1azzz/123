#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include <stdint.h>
#include "filesys/file.h"

#include "threads/synch.h" // 为了使用信号量 (semaphores)
#include "lib/kernel/list.h" // 为了使用链表 (lists)

// At most 8MB can be allocated to the stack
// These defines will be used in Project 2: Multithreading
#define MAX_STACK_PAGES (1 << 11)
#define MAX_THREADS 127
#define MAX_OPEN_FILES 128

/* PIDs and TIDs are the same type. PID should be
   the TID of the main thread of the process */
typedef tid_t pid_t;

/* Thread functions (Project 2: Multithreading) */
typedef void (*pthread_fun)(void *);
typedef void (*stub_fun)(pthread_fun, void *);

struct process;   //声明

struct load_helper {
   char *file_name_with_args;
   struct semaphore wait_sema;
   bool load_success;
   pid_t child_pid;
   struct process *parent_pcb;

   struct semaphore child_start_sema; // 新增：子进程等待父进程完成添加
};

// fork辅助结构体，用于父子进程间同步
struct fork_helper {
   struct semaphore wait_sema;          // 父进程等待子进程初始化完成
   struct semaphore child_start_sema;   // 子进程等待父进程完成记录
   bool load_success;                   // 子进程初始化是否成功
   pid_t child_pid;                     // 子进程PID
   struct process *parent_pcb;          // 父进程PCB
   struct process *child_pcb;           // 子进程PCB
   struct intr_frame *parent_if;        // 父进程中断帧
};

struct child_status {
   pid_t child_pid;                // 子进程的 PID
   int exit_code;                  // 子进程的退出状态码
   bool has_exited;                // 标记子进程是否已经退出
   bool parent_has_waited;         // 标记父进程是否已经对该子进程调用过 wait
   struct semaphore wait_sema;     // 父进程在此信号量上等待子进程退出
   struct list_elem elem;          // 用于链表连接的元素
};


/* The process control block for a given process. Since
   there can be multiple threads per process, we need a separate
   PCB from the TCB. All TCBs in a process will have a pointer
   to the PCB, and the PCB will have a pointer to the main thread
   of the process, which is `special`. */
struct process {
   /* 由 process.c 拥有。 */
   uint32_t *pagedir;                  /* 页目录。 */
   char process_name[16];              /* 主线程的名称 (通常是可执行文件名) */
   struct thread *main_thread;         /* 指向主线程的指针 */
   struct file *fd_table[MAX_OPEN_FILES]; /* 文件描述符表 */
   int next_fd;                        /* 下一个可用的文件描述符索引 (从2开始，0和1为STDIN/STDOUT) */

   /* 为 fork, wait, exec 添加的成员 */
   pid_t pid;                          /* 当前进程的 PID */
   struct process *parent_pcb;         /* 指向父进程 PCB 的指针。对于初始进程(init)可以为 NULL */

   struct list children_list;          /* 子进程列表 (元素类型为 struct child_status) */
   /* 父进程用此列表追踪其所有子进程的状态 */

   int exit_code;                      /* 进程退出时要报告给父进程的退出状态码 */
   bool is_exited;                     /* 标记此进程是否已调用 process_exit */

   struct file *executable_file;       /* 指向当前运行的可执行文件的指针。*/
   /* exec 时关闭旧的，打开新的。fork 时复制。*/
   /* 进程退出时关闭。*/

   // 用于同步对 fd_table 或其他共享进程资源的访问，例如在 fork 期间
   struct lock process_lock;

   // --- 新增用于全局进程列表的元素 ---
   struct list_elem global_elem; /* 用于加入全局进程列表 all_processes_list */
};

void userprog_init(void);

pid_t process_execute(const char *file_name);
int process_wait(pid_t);
void process_exit(void);
void process_activate(void);

pid_t process_fork(const char *thread_name, struct intr_frame *parent_if);

bool is_main_thread(struct thread *, struct process *);
pid_t get_pid(struct process *);

tid_t pthread_execute(stub_fun, pthread_fun, void *);
tid_t pthread_join(tid_t);
void pthread_exit(void);
void pthread_exit_main(void);

#endif /* userprog/process.h */
