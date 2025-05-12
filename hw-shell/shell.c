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

int cmd_exit(struct tokens* tokens);
int cmd_help(struct tokens *tokens);
int cmd_pwd(struct tokens *tokens);
int cmd_cd(struct tokens *tokens);

/* Built-in command functions take token array (see parse.h) and return int */
typedef int cmd_fun_t(struct tokens* tokens);

/* Built-in command struct and lookup table */
typedef struct fun_desc {
  cmd_fun_t* fun;
  char* cmd;
  char* doc;
} fun_desc_t;

fun_desc_t cmd_table[] = {
    {cmd_help, "?", "show this help menu"},
    {cmd_exit, "exit", "exit the command shell"},
    {cmd_pwd, "pwd", "print working directory"},
    {cmd_cd, "cd", "change directory"}
};

/* Prints a helpful description for the given command */
int cmd_help(unused struct tokens* tokens) {
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

int main(unused int argc, unused char* argv[]) {
  init_shell();

  static char line[4096];
  int line_num = 0;

  /* Please only print shell prompts when standard input is not a tty */
  if (shell_is_interactive)
    fprintf(stdout, "%d: ", line_num);

  while (fgets(line, 4096, stdin)) {
    /* Split our line into words. */
    struct tokens *tokens = tokenize(line);

    /* Find which built-in function to run. */
    int fundex = lookup(tokens_get_token(tokens, 0));

    if (fundex >= 0) {
      cmd_table[fundex].fun(tokens);
    } else {
      size_t argc = tokens_get_length(tokens);
      if (argc == 0) {
        continue;
      }

      pid_t pid;
      int status;

      // 创建子进程执行外部命令
      pid = fork();

      if (pid == -1) {
        // fork失败
        perror("fork");
      } else if (pid == 0) {
        // 子进程代码

        // 获取程序路径（第一个参数）
        const char *program_path = tokens_get_token(tokens, 0);

        // 创建参数数组，包括程序名称和NULL终止符
        char **args = malloc((argc + 1) * sizeof(char *));
        if (args == NULL) {
          perror("malloc");
          exit(1);
        }

        // 将所有token复制到参数数组中
        for (size_t i = 0; i < argc; i++) {
          args[i] = tokens_get_token(tokens, i);
        }
        args[argc] = NULL; // 确保参数数组以NULL结尾

        // 执行程序
        execv(program_path, args);

        // 如果execv返回，则出错
        perror("execv");
        free(args);
        exit(1);
      } else {
        // 等待子进程结束
        if (waitpid(pid, &status, 0) == -1) {
          perror("waitpid");
        }
      }
    }

    if (shell_is_interactive)
      /* Please only print shell prompts when standard input is not a tty */
      fprintf(stdout, "%d: ", ++line_num);

    /* Clean up memory */
    tokens_destroy(tokens);
  }

  return 0;
}
