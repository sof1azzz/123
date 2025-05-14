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

int cmd_exit(struct tokens *tokens);
int cmd_help(struct tokens *tokens);
int cmd_pwd(struct tokens *tokens);
int cmd_cd(struct tokens *tokens);

// helper
char *resolve_path(const char *cmd);
void handle_redirection(struct tokens *tokens, int *input_fd, int *output_fd, char ***cmd_args, int *arg_count);
void execute_command(char **args, int input_fd, int output_fd);
void run_command_pipeline(struct tokens *tokens);

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
}

// 处理包含管道的命令
void run_command_pipeline(struct tokens *tokens) {
  size_t token_count = tokens_get_length(tokens);
  if (token_count == 0) {
    return;  // 空命令
  }

  // 计算管道数量
  int pipe_count = 0;
  for (size_t i = 0; i < token_count; i++) {
    if (strcmp(tokens_get_token(tokens, i), "|") == 0) {
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

    // 等待子进程结束
    int status;
    wait(&status);

    // 清理
    for (int i = 0; i < arg_count; i++) {
      free(args[i]);
    }
    free(args);
    return;
  }

  // 有管道，需要分段处理
  int pipes[pipe_count][2];
  char ***commands = malloc((pipe_count + 1) * sizeof(char **));
  int *command_lengths = malloc((pipe_count + 1) * sizeof(int));

  if (!commands || !command_lengths) {
    perror("malloc");
    exit(1);
  }

  // 初始化所有管道
  for (int i = 0; i < pipe_count; i++) {
    if (pipe(pipes[i]) == -1) {
      perror("pipe");
      exit(1);
    }
  }

  // 解析命令和参数
  int cmd_idx = 0;
  int start_idx = 0;

  for (size_t i = 0; i <= token_count; i++) {
    if (i == token_count || strcmp(tokens_get_token(tokens, i), "|") == 0) {
      // 提取一个命令段
      int cmd_len = i - start_idx;
      if (cmd_len <= 0) {
        fprintf(stderr, "语法错误：管道符号周围缺少命令\n");
        exit(1);
      }

      // 为这个命令分配参数数组
      commands[cmd_idx] = malloc((cmd_len + 1) * sizeof(char *));
      if (!commands[cmd_idx]) {
        perror("malloc");
        exit(1);
      }

      // 复制参数
      for (int j = 0; j < cmd_len; j++) {
        commands[cmd_idx][j] = strdup(tokens_get_token(tokens, start_idx + j));
      }
      commands[cmd_idx][cmd_len] = NULL;
      command_lengths[cmd_idx] = cmd_len;

      cmd_idx++;
      start_idx = i + 1;  // 跳过管道符号
    }
  }

  // 执行管道命令链
  pid_t *pids = malloc((pipe_count + 1) * sizeof(pid_t));
  if (!pids) {
    perror("malloc");
    exit(1);
  }

  for (int i = 0; i <= pipe_count; i++) {
    pids[i] = fork();

    if (pids[i] == -1) {
      perror("fork");
      exit(1);
    } else if (pids[i] == 0) {  // 子进程
      // 设置管道连接
      if (i > 0) {  // 不是第一个命令，从前一个管道读取输入
        dup2(pipes[i - 1][0], STDIN_FILENO);
      }

      if (i < pipe_count) {  // 不是最后一个命令，输出到下一个管道
        dup2(pipes[i][1], STDOUT_FILENO);
      }

      // 关闭所有管道描述符
      for (int j = 0; j < pipe_count; j++) {
        close(pipes[j][0]);
        close(pipes[j][1]);
      }

      // 检查重定向
      int input_fd = STDIN_FILENO;
      int output_fd = STDOUT_FILENO;

      // 解析程序完整路径
      char *program_path = resolve_path(commands[i][0]);
      if (program_path == NULL) {
        fprintf(stderr, "%s: 命令未找到\n", commands[i][0]);
        exit(1);
      }

      // 执行程序
      execv(program_path, commands[i]);

      // 如果execv返回，则出错
      perror("execv");
      free(program_path);
      exit(1);
    }
  }

  // 父进程关闭所有管道描述符
  for (int i = 0; i < pipe_count; i++) {
    close(pipes[i][0]);
    close(pipes[i][1]);
  }

  // 等待所有子进程结束
  for (int i = 0; i <= pipe_count; i++) {
    int status;
    waitpid(pids[i], &status, 0);
  }

  // 清理资源
  for (int i = 0; i <= pipe_count; i++) {
    for (int j = 0; j < command_lengths[i]; j++) {
      free(commands[i][j]);
    }
    free(commands[i]);
  }
  free(commands);
  free(command_lengths);
  free(pids);
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