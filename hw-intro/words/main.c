/*

  Word Count using dedicated lists

*/

/*
Copyright © 2019 University of California, Berkeley

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#include <assert.h>
#include <getopt.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdlib.h>

#include "word_count.h"

/* Global data structure tracking the words encountered */
WordCount *word_counts = NULL;

/* The maximum length of each word in a file */
#define MAX_WORD_LEN 64

/*
 * 3.1.1 Total Word Count
 *
 * Returns the total amount of words found in infile.
 * Useful functions: fgetc(), isalpha().
 */
int num_words(FILE *infile) {
    int num_words = 0;
    int c;
    bool in_word = false;

    while ((c = fgetc(infile)) != EOF) {
        if (isalpha(c)) {
            // 找到了一个字母字符
            if (!in_word) {
                in_word = true;
            }
        } else {
            // 找到了一个非字母字符
            if (in_word) {
                num_words++;
                in_word = false;
            }
        }
    }

    // 处理文件末尾可能的最后一个单词
    if (in_word) {
        num_words++;
    }

    // 重置文件指针到文件开头
    rewind(infile);
    return num_words;
}

/*
 * 3.1.2 Word Frequency Count
 *
 * Given infile, extracts and adds each word in the FILE to `wclist`.
 * Useful functions: fgetc(), isalpha(), tolower(), add_word().
 *
 * As mentioned in the spec, your code should not panic or
 * segfault on errors. Thus, this function should return
 * 1 in the event of any errors (e.g. wclist or infile is NULL)
 * and 0 otherwise.
 */
int count_words(WordCount **wclist, FILE *infile) {
    if (wclist == NULL || infile == NULL) {
        return 1;  // 错误：空指针
    }

    char word_buffer[MAX_WORD_LEN];
    int c;
    int count = 0;
    bool in_word = false;

    while ((c = fgetc(infile)) != EOF) {
        if (isalpha(c)) {
            if (count < MAX_WORD_LEN - 1) {
                word_buffer[count++] = tolower(c);  // 构建小写单词
            }
            in_word = true;
        } else if (in_word) {
            word_buffer[count] = '\0';  // 字符串结尾
            if (count > 1) {
                add_word(wclist, word_buffer);  // 添加单词
            }
            count = 0;
            in_word = false;
        }
    }

    // 处理文件末尾可能剩余的一个单词
    if (in_word && count > 1) {
        word_buffer[count] = '\0';
        add_word(wclist, word_buffer);
    }

    // 重置文件指针到文件开头
    rewind(infile);
    return 0;  // 成功
}

/*
 * Comparator to sort list by frequency.
 * Useful function: strcmp().
 */
static bool wordcount_less(const WordCount *wc1, const WordCount *wc2) {
    if (wc1->count != wc2->count) {
        return wc1->count < wc2->count;
    }
    return strcmp(wc1->word, wc2->word) < 0;
}

// In trying times, displays a helpful message.
static int display_help(void) {
    printf("Flags:\n"
        "--count (-c): Count the total amount of words in the file, or STDIN if a file is not specified. This is default behavior if no flag is specified.\n"
        "--frequency (-f): Count the frequency of each word in the file, or STDIN if a file is not specified.\n"
        "--help (-h): Displays this help message.\n");
    return 0;
}

/*
 * Handle command line flags and arguments.
 */
int main(int argc, char *argv[]) {

    // Count Mode (default): outputs the total amount of words counted
    bool count_mode = true;
    int total_words = 0;

    // Freq Mode: outputs the frequency of each word
    bool freq_mode = false;

    FILE *infile = NULL;

    // Variables for command line argument parsing
    int i;
    static struct option long_options[] =
    {
        {"count", no_argument, 0, 'c'},
        {"frequency", no_argument, 0, 'f'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    // Sets flags
    while ((i = getopt_long(argc, argv, "cfh", long_options, NULL)) != -1) {
        switch (i) {
        case 'c':
            count_mode = true;
            freq_mode = false;
            break;
        case 'f':
            count_mode = false;
            freq_mode = true;
            break;
        case 'h':
            return display_help();
        }
    }

    if (!count_mode && !freq_mode) {
        printf("Please specify a mode.\n");
        return display_help();
    }

    /* Create the empty data structure */
    init_words(&word_counts);

    if ((argc - optind) < 1) {
        // 没有指定输入文件，从标准输入读取
        if (count_mode) {
            total_words = num_words(stdin);
        } else {
            count_words(&word_counts, stdin);
        }
    } else {
        // 至少指定了一个文件
        for (i = optind; i < argc; i++) {
            infile = fopen(argv[i], "r");
            if (infile == NULL) {
                fprintf(stderr, "Error: Cannot open file %s\n", argv[i]);
                continue;
            }

            if (count_mode) {
                total_words += num_words(infile);
            } else {
                count_words(&word_counts, infile);
            }

            fclose(infile);
        }
    }

    if (count_mode) {
        printf("The total number of words is: %i\n", total_words);
    } else {
        wordcount_sort(&word_counts, wordcount_less);

        printf("The frequencies of each word are: \n");
        fprint_words(word_counts, stdout);
    }
    return 0;
}