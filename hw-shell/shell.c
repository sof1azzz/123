#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#include "tokenizer.h"

/* Convenience macro to silence compiler warnings about unused function parameters. */
#define unused __attribute__((unused))

/* Whether the shell is connected to an actual terminal or not. */
bool shell_is_interactive;

/* File descriptor for the shell input */
int shell_terminal;

/* Terminal mode settings for the shell */
struct termios shell_tmodes;

/* Process group id for the shell */
pid_t shell_pgid;

/* 当前前台进程组ID */
pid_t foreground_pgid = 0;

int cmd_exit(struct tokens *tokens);
int cmd_help(struct tokens *tokens);
int cmd_pwd(struct tokens *tokens);
int cmd_cd(struct tokens *tokens);

// helper
char *resolve_path(const char *cmd);
void handle_redirection(struct tokens *tokens, int *input_fd, int *output_fd, char ***cmd_args, int *arg_count);
void execute_command(char **args, int input_fd, int output_fd);
void run_command_pipeline(struct tokens *tokens);
void setup_signal_handlers(void);
void sigint_handler(int sig);
void sigtstp_handler(int sig);
void wait_for_foreground_job(pid_t pgid);

/* Built-in command functions take token array (see parse.h) and return int */
typedef int cmd_fun_t(struct tokens *tokens);

/* Built-in command struct and lookup table */
typedef struct fun_desc {
  cmd_fun_t *fun;
  char *cmd;
  char *doc;
} fun_desc_t;

fun_desc_t cmd_table[] = {
    {cmd_help, "?", "show this help menu"},
    {cmd_exit, "exit", "exit the command shell"},
    {cmd_pwd, "pwd", "print working directory"},
    {cmd_cd, "cd", "change directory"}
};

/* Prints a helpful description for the given command */
int cmd_help(unused struct tokens *tokens) {
  for (unsigned int i = 0; i < sizeof(cmd_table) / sizeof(fun_desc_t); i++)
    printf("%s - %s\n", cmd_table[i].cmd, cmd_table[i].doc);
  return 1;
}

/* Exits this shell */
int cmd_exit(unused struct tokens *tokens) { exit(0); }

int cmd_pwd(struct tokens *tokens) {
  char cwd[1024];  // 足够大的缓冲区
  if (getcwd(cwd, sizeof(cwd)) != NULL) {
    printf("%s\n", cwd);
    return 1;
  } else {
    perror("getcwd");
    return -1;
  }
}

int cmd_cd(struct tokens *tokens) {
  size_t argc = tokens_get_length(tokens);

  if (argc == 1) {
    // 没有提供目标目录，默认切换到用户的家目录
    const char *home = getenv("HOME");
    if (home == NULL) {
      fprintf(stderr, "cd: 无法获取HOME环境变量\n");
      return -1;
    }
    if (chdir(home) != 0) {
      perror("cd");
      return -1;
    }
  } else if (argc == 2) {
    // 提供了目标目录
    const char *path = tokens_get_token(tokens, 1);
    if (chdir(path) != 0) {
      perror("cd");
      return -1;
    }
  } else {
    // 参数过多
    fprintf(stderr, "用法: cd [目录]\n");
    return -1;
  }

  return 1;
}

/* Looks up the built-in command, if it exists. */
int lookup(char cmd[]) {
  for (unsigned int i = 0; i < sizeof(cmd_table) / sizeof(fun_desc_t); i++)
    if (cmd && (strcmp(cmd_table[i].cmd, cmd) == 0))
      return i;
  return -1;
}

/* 信号处理器：处理SIGINT（Ctrl+C）*/
void sigint_handler(int sig) {
  if (foreground_pgid > 0) {
    // 如果有前台进程组，向其发送SIGINT信号
    kill(-foreground_pgid, SIGINT);
  } else {
    // 如果没有前台作业，则重新显示提示符
    printf("\n");
    fflush(stdout);
  }
}

/* 信号处理器：处理SIGTSTP（Ctrl+Z）*/
void sigtstp_handler(int sig) {
  if (foreground_pgid > 0) {
    // 如果有前台进程组，向其发送SIGTSTP信号
    kill(-foreground_pgid, SIGTSTP);
  } else {
    // 如果没有前台作业，则重新显示提示符
    printf("\n");
    fflush(stdout);
  }
}

/* 设置信号处理器 */
void setup_signal_handlers(void) {
  // 忽略交互式停止信号
  signal(SIGTTOU, SIG_IGN);
  signal(SIGTTIN, SIG_IGN);
  signal(SIGTSTP, sigtstp_handler);
  signal(SIGINT, sigint_handler);
}

/* 等待前台作业完成 */
void wait_for_foreground_job(pid_t pgid) {
  int status;
  pid_t pid;

  // 保存当前前台进程组ID
  foreground_pgid = pgid;
  
  // 将进程组置于前台
  if (shell_is_interactive) {
    tcsetpgrp(shell_terminal, pgid);
  }
  
  // 等待所有进程结束
  while ((pid = waitpid(-pgid, &status, WUNTRACED)) > 0) {
    // 进程结束或被暂停
  }
  
  // 将shell重新置于前台
  if (shell_is_interactive) {
    tcsetpgrp(shell_terminal, shell_pgid);
  }
  
  // 清除前台进程组ID
  foreground_pgid = 0;
}

/* Intialization procedures for this shell */
void init_shell() {
  /* Our shell is connected to standard input. */
  shell_terminal = STDIN_FILENO;

  /* Check if we are running interactively */
  shell_is_interactive = isatty(shell_terminal);

  if (shell_is_interactive) {
    /* If the shell is not currently in the foreground, we must pause the shell until it becomes a
     * foreground process. We use SIGTTIN to pause the shell. When the shell gets moved to the
     * foreground, we'll receive a SIGCONT. */
    while (tcgetpgrp(shell_terminal) != (shell_pgid = getpgrp()))
      kill(-shell_pgid, SIGTTIN);

    /* Saves the shell's process id */
    shell_pgid = getpid();

    /* Take control of the terminal */
    tcsetpgrp(shell_terminal, shell_pgid);

    /* Save the current termios to a variable, so it can be restored later. */
    tcgetattr(shell_terminal, &shell_tmodes);
    
    /* 设置信号处理器 */
    setup_signal_handlers();
    
    /* 确保shell在自己的进程组中 */
    if (setpgid(shell_pgid, shell_pgid) < 0) {
      perror("setpgid");
      exit(1);
    }
  }
}

// 处理重定向符号
void handle_redirection(struct tokens *tokens, int *input_fd, int *output_fd, char ***cmd_args, int *arg_count) {
  size_t token_count = tokens_get_length(tokens);
  *arg_count = 0;

  // 分配足够的空间用于存储命令参数
  *cmd_args = malloc((token_count + 1) * sizeof(char *));
  if (*cmd_args == NULL) {
    perror("malloc");
    exit(1);
  }

  // 初始化文件描述符
  *input_fd = STDIN_FILENO;   // 默认输入
  *output_fd = STDOUT_FILENO; // 默认输出

  // 遍历所有token，寻找重定向符号
  for (size_t i = 0; i < token_count; i++) {
    const char *token = tokens_get_token(tokens, i);

    if (strcmp(token, "<") == 0) {
      // 输入重定向
      if (i + 1 < token_count) {
        const char *file = tokens_get_token(tokens, i + 1);
        *input_fd = open(file, O_RDONLY);
        if (*input_fd == -1) {
          fprintf(stderr, "打开输入文件 %s 失败: %s\n", file, strerror(errno));
          *input_fd = STDIN_FILENO; // 恢复默认输入
        }
        i++; // 跳过文件名
      } else {
        fprintf(stderr, "输入重定向符号后缺少文件名\n");
      }
    } else if (strcmp(token, ">") == 0) {
      // 输出重定向
      if (i + 1 < token_count) {
        const char *file = tokens_get_token(tokens, i + 1);
        *output_fd = open(file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (*output_fd == -1) {
          fprintf(stderr, "打开输出文件 %s 失败: %s\n", file, strerror(errno));
          *output_fd = STDOUT_FILENO; // 恢复默认输出
        }
        i++; // 跳过文件名
      } else {
        fprintf(stderr, "输出重定向符号后缺少文件名\n");
      }
    } else if (strcmp(token, ">>") == 0) {
      // 追加输出重定向
      if (i + 1 < token_count) {
        const char *file = tokens_get_token(tokens, i + 1);
        *output_fd = open(file, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (*output_fd == -1) {
          fprintf(stderr, "打开输出文件 %s 失败: %s\n", file, strerror(errno));
          *output_fd = STDOUT_FILENO; // 恢复默认输出
        }
        i++; // 跳过文件名
      } else {
        fprintf(stderr, "追加重定向符号后缺少文件名\n");
      }
    } else {
      // 普通参数，添加到命令参数列表
      (*cmd_args)[*arg_count] = strdup(token);
      (*arg_count)++;
    }
  }

  // 确保命令参数列表以NULL结尾
  (*cmd_args)[*arg_count] = NULL;
}

// 执行单个命令，处理输入和输出重定向
void execute_command(char **args, int input_fd, int output_fd) {
  if (args[0] == NULL) {
    return;  // 空命令
  }

  // 检查是否是内置命令
  int fundex = lookup(args[0]);
  if (fundex >= 0) {
    // 创建临时的tokens结构用于内置命令
    struct tokens *temp_tokens = tokens_create();
    for (int i = 0; args[i] != NULL; i++) {
      tokens_add(temp_tokens, args[i]);
    }
    
    // 保存原始的标准输入输出
    int saved_stdin = dup(STDIN_FILENO);
    int saved_stdout = dup(STDOUT_FILENO);
    
    // 设置重定向
    if (input_fd != STDIN_FILENO) {
      dup2(input_fd, STDIN_FILENO);
      close(input_fd);
    }
    if (output_fd != STDOUT_FILENO) {
      dup2(output_fd, STDOUT_FILENO);
      close(output_fd);
    }
    
    // 执行内置命令
    cmd_table[fundex].fun(temp_tokens);
    
    // 恢复标准输入输出
    dup2(saved_stdin, STDIN_FILENO);
    dup2(saved_stdout, STDOUT_FILENO);
    close(saved_stdin);
    close(saved_stdout);
    
    // 清理
    tokens_destroy(temp_tokens);
    return;
  }

  // 外部命令，创建子进程执行
  pid_t pid = fork();
  
  if (pid == -1) {
    perror("fork");
    return;
  } else if (pid == 0) {  // 子进程
    // 创建新的进程组
    if (shell_is_interactive) {
      pid_t child_pid = getpid();
      setpgid(child_pid, child_pid);
    }
    
    // 设置输入重定向
    if (input_fd != STDIN_FILENO) {
      dup2(input_fd, STDIN_FILENO);
      close(input_fd);
    }
    
    // 设置输出重定向
    if (output_fd != STDOUT_FILENO) {
      dup2(output_fd, STDOUT_FILENO);
      close(output_fd);
    }
    
    // 解析程序完整路径
    char *program_path = resolve_path(args[0]);
    if (program_path == NULL) {
      fprintf(stderr, "%s: 命令未找到\n", args[0]);
      exit(1);
    }
    
    // 执行程序
    execv(program_path, args);
    
    // 如果execv返回，则出错
    perror("execv");
    free(program_path);
    exit(1);
  }
  
  // 父进程不需要这些文件描述符
  if (input_fd != STDIN_FILENO) {
    close(input_fd);
  }
  if (output_fd != STDOUT_FILENO) {
    close(output_fd);
  }
  
  // 确保子进程在同一个进程组
  if (shell_is_interactive) {
    setpgid(pid, pid);
  }
  
  // 等待前台命令完成
  wait_for_foreground_job(pid);
}

// 处理包含管道的命令
void run_command_pipeline(struct tokens *tokens) {
  size_t token_count = tokens_get_length(tokens);
  if (token_count == 0) {
    return;  // 空命令
  }
  
  // 计算管道数量和分割命令
  int pipe_count = 0;
  int pipe_positions[token_count]; // 存储管道符号的位置
  
  for (size_t i = 0; i < token_count; i++) {
    if (strcmp(tokens_get_token(tokens, i), "|") == 0) {
      pipe_positions[pipe_count] = i;
      pipe_count++;
    }
  }
  
  if (pipe_count == 0) {
    // 没有管道，直接执行单个命令
    int input_fd, output_fd;
    char **args;
    int arg_count;
    handle_redirection(tokens, &input_fd, &output_fd, &args, &arg_count);
    execute_command(args, input_fd, output_fd);
    
    // 清理
    for (int i = 0; i < arg_count; i++) {
      free(args[i]);
    }
    free(args);
    return;
  }
  
  // 有管道，需要分段处理
  int pipes[pipe_count][2];
  
  // 初始化所有管道
  for (int i = 0; i < pipe_count; i++) {
    if (pipe(pipes[i]) == -1) {
      perror("pipe");
      exit(1);
    }
  }
  
  // 创建子进程数组
  pid_t pids[pipe_count + 1];
  pid_t pgid = 0;  // 进程组ID
  
  // 创建第一段命令的子进程
  pids[0] = fork();
  if (pids[0] == -1) {
    perror("fork");
    exit(1);
  } else if (pids[0] == 0) {  // 子进程
    // 获取进程ID并设置进程组
    pid_t pid = getpid();
    if (shell_is_interactive) {
      if (pgid == 0) pgid = pid;
      setpgid(pid, pgid);
    }
    
    // 创建第一段命令的tokens子集
    struct tokens *cmd_tokens = tokens_create();
    for (int j = 0; j < pipe_positions[0]; j++) {
      tokens_add(cmd_tokens, tokens_get_token(tokens, j));
    }
    
    // 处理第一段命令的重定向
    int input_fd, output_fd;
    char **args;
    int arg_count;
    
    // 默认输出设置为第一个管道的写端
    handle_redirection(cmd_tokens, &input_fd, &output_fd, &args, &arg_count);
    
    // 关闭所有不需要的管道端
    for (int j = 0; j < pipe_count; j++) {
      if (j == 0) {
        // 第一个命令，输出到第一个管道
        if (output_fd == STDOUT_FILENO) { // 如果没有重定向输出
          dup2(pipes[0][1], STDOUT_FILENO);
        }
        close(pipes[j][0]); // 关闭读端
      } else {
        close(pipes[j][0]);
        close(pipes[j][1]);
      }
    }
    
    tokens_destroy(cmd_tokens);
    
    // 执行命令
    if (args[0] == NULL) {
      fprintf(stderr, "语法错误：管道符号前缺少命令\n");
      exit(1);
    }
    
    char *program_path = resolve_path(args[0]);
    if (program_path == NULL) {
      fprintf(stderr, "%s: 命令未找到\n", args[0]);
      exit(1);
    }
    
    // 设置输入重定向
    if (input_fd != STDIN_FILENO) {
      dup2(input_fd, STDIN_FILENO);
      close(input_fd);
    }
    
    // 如果有输出重定向，它已经由handle_redirection处理
    if (output_fd != STDOUT_FILENO && output_fd != pipes[0][1]) {
      dup2(output_fd, STDOUT_FILENO);
      close(output_fd);
      close(pipes[0][1]); // 关闭管道写端，因为我们使用了重定向
    }
    
    execv(program_path, args);
    perror("execv");
    
    // 清理
    for (int j = 0; j < arg_count; j++) {
      free(args[j]);
    }
    free(args);
    free(program_path);
    exit(1);
  } else {
    // 父进程保存第一个子进程的PID作为进程组ID
    pgid = pids[0];
    if (shell_is_interactive) {
      setpgid(pids[0], pgid);
    }
  }
  
  // 创建中间段命令的子进程
  for (int i = 1; i < pipe_count; i++) {
    pids[i] = fork();
    if (pids[i] == -1) {
      perror("fork");
      exit(1);
    } else if (pids[i] == 0) {  // 子进程
      // 设置进程组
      if (shell_is_interactive) {
        setpgid(getpid(), pgid);
      }
      
      // 创建此段命令的tokens子集
      struct tokens *cmd_tokens = tokens_create();
      for (int j = pipe_positions[i-1] + 1; j < pipe_positions[i]; j++) {
        tokens_add(cmd_tokens, tokens_get_token(tokens, j));
      }
      
      // 处理此段命令的重定向
      int input_fd, output_fd;
      char **args;
      int arg_count;
      
      handle_redirection(cmd_tokens, &input_fd, &output_fd, &args, &arg_count);
      
      // 关闭所有不需要的管道端
      for (int j = 0; j < pipe_count; j++) {
        if (j == i - 1) {
          // 从上一个管道读取
          if (input_fd == STDIN_FILENO) { // 如果没有重定向输入
            dup2(pipes[j][0], STDIN_FILENO);
          }
        } else if (j == i) {
          // 输出到下一个管道
          if (output_fd == STDOUT_FILENO) { // 如果没有重定向输出
            dup2(pipes[j][1], STDOUT_FILENO);
          }
        }
        close(pipes[j][0]);
        close(pipes[j][1]);
      }
      
      tokens_destroy(cmd_tokens);
      
      // 执行命令
      if (args[0] == NULL) {
        fprintf(stderr, "语法错误：管道符号之间缺少命令\n");
        exit(1);
      }
      
      char *program_path = resolve_path(args[0]);
      if (program_path == NULL) {
        fprintf(stderr, "%s: 命令未找到\n", args[0]);
        exit(1);
      }
      
      // 设置输入重定向
      if (input_fd != STDIN_FILENO && input_fd != pipes[i-1][0]) {
        dup2(input_fd, STDIN_FILENO);
        close(input_fd);
      }
      
      // 设置输出重定向
      if (output_fd != STDOUT_FILENO && output_fd != pipes[i][1]) {
        dup2(output_fd, STDOUT_FILENO);
        close(output_fd);
      }
      
      execv(program_path, args);
      perror("execv");
      
      // 清理
      for (int j = 0; j < arg_count; j++) {
        free(args[j]);
      }
      free(args);
      free(program_path);
      exit(1);
    } else {
      // 父进程设置子进程的进程组
      if (shell_is_interactive) {
        setpgid(pids[i], pgid);
      }
    }
  }
  
  // 创建最后一段命令的子进程
  pids[pipe_count] = fork();
  if (pids[pipe_count] == -1) {
    perror("fork");
    exit(1);
  } else if (pids[pipe_count] == 0) {  // 子进程
    // 设置进程组
    if (shell_is_interactive) {
      setpgid(getpid(), pgid);
    }
    
    // 创建最后一段命令的tokens子集
    struct tokens *cmd_tokens = tokens_create();
    for (int j = pipe_positions[pipe_count-1] + 1; j < token_count; j++) {
      tokens_add(cmd_tokens, tokens_get_token(tokens, j));
    }
    
    // 处理最后一段命令的重定向
    int input_fd, output_fd;
    char **args;
    int arg_count;
    
    handle_redirection(cmd_tokens, &input_fd, &output_fd, &args, &arg_count);
    
    // 关闭所有不需要的管道端
    for (int j = 0; j < pipe_count; j++) {
      if (j == pipe_count - 1) {
        // 最后一个命令，从最后一个管道读取
        if (input_fd == STDIN_FILENO) { // 如果没有重定向输入
          dup2(pipes[j][0], STDIN_FILENO);
        }
        close(pipes[j][1]); // 关闭写端
      } else {
        close(pipes[j][0]);
        close(pipes[j][1]);
      }
    }
    
    tokens_destroy(cmd_tokens);
    
    // 执行命令
    if (args[0] == NULL) {
      fprintf(stderr, "语法错误：管道符号后缺少命令\n");
      exit(1);
    }
    
    char *program_path = resolve_path(args[0]);
    if (program_path == NULL) {
      fprintf(stderr, "%s: 命令未找到\n", args[0]);
      exit(1);
    }
    
    // 设置输入重定向
    if (input_fd != STDIN_FILENO && input_fd != pipes[pipe_count-1][0]) {
      dup2(input_fd, STDIN_FILENO);
      close(input_fd);
    }
    
    // 输出重定向已经由handle_redirection处理
    
    execv(program_path, args);
    perror("execv");
    
    // 清理
    for (int j = 0; j < arg_count; j++) {
      free(args[j]);
    }
    free(args);
    free(program_path);
    exit(1);
  } else {
    // 父进程设置子进程的进程组
    if (shell_is_interactive) {
      setpgid(pids[pipe_count], pgid);
    }
  }
  
  // 父进程关闭所有管道描述符
  for (int i = 0; i < pipe_count; i++) {
    close(pipes[i][0]);
    close(pipes[i][1]);
  }
  
  // 等待所有子进程结束
  wait_for_foreground_job(pgid);
}

int main(unused int argc, unused char *argv[]) {
  init_shell();

  static char line[4096];
  int line_num = 0;

  /* Please only print shell prompts when standard input is not a tty */
  if (shell_is_interactive)
    fprintf(stdout, "%d: ", line_num);

  while (fgets(line, 4096, stdin)) {
    /* Split our line into words. */
    struct tokens *tokens = tokenize(line);

    /* 检查是否是空命令 */
    if (tokens_get_length(tokens) == 0) {
      if (shell_is_interactive)
        fprintf(stdout, "%d: ", ++line_num);
      tokens_destroy(tokens);
      continue;
    }

    /* 检查命令是否是内置命令 */
    int fundex = lookup(tokens_get_token(tokens, 0));

    if (fundex >= 0) {
      cmd_table[fundex].fun(tokens);
    } else {
      /* 处理外部命令，包括管道 */
      run_command_pipeline(tokens);
    }

    if (shell_is_interactive)
      /* Please only print shell prompts when standard input is not a tty */
      fprintf(stdout, "%d: ", ++line_num);

    /* Clean up memory */
    tokens_destroy(tokens);
  }

  return 0;
}

char *resolve_path(const char *cmd) {
  // 如果cmd包含'/'，说明它是一个路径，直接返回其副本
  if (strchr(cmd, '/') != NULL) {
    return strdup(cmd);
  }

  // 从环境变量获取PATH
  const char *path_env = getenv("PATH");
  if (path_env == NULL) {
    return NULL; // 没有PATH环境变量
  }

  // 复制PATH字符串，因为strtok_r会修改它
  char *path_copy = strdup(path_env);
  if (path_copy == NULL) {
    return NULL; // 内存分配失败
  }

  char *path_token;
  char *path_save_ptr;
  char *resolved_path = NULL;

  // 遍历PATH中的每个目录
  for (path_token = strtok_r(path_copy, ":", &path_save_ptr);
    path_token != NULL;
    path_token = strtok_r(NULL, ":", &path_save_ptr)) {

    // 构建完整的可能路径
    size_t dir_len = strlen(path_token);
    size_t cmd_len = strlen(cmd);
    size_t path_len = dir_len + 1 + cmd_len + 1; // +1 for '/' and +1 for '\0'

    char *full_path = malloc(path_len);
    if (full_path == NULL) {
      continue; // 内存分配失败，尝试下一个目录
    }

    // 组合目录和命令
    strcpy(full_path, path_token);
    full_path[dir_len] = '/';
    strcpy(full_path + dir_len + 1, cmd);

    // 检查文件是否存在且可执行
    if (access(full_path, X_OK) == 0) {
      resolved_path = full_path;
      break;
    }

    // 这个路径不存在或不可执行，释放内存并尝试下一个
    free(full_path);
  }

  // 释放PATH副本
  free(path_copy);

  return resolved_path;
} 