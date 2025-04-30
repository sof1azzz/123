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

word_count provides lists of words and associated count

Functional methods take the head of a list as first arg.
Mutators take a reference to a list as first arg.
*/

#include "word_count.h"

/* Basic utilities */

char *new_string(char *str) {
    char *new_str = (char *)malloc(strlen(str) + 1);
    if (new_str == NULL) {
        return NULL;
    }
    return strcpy(new_str, str);
}

int init_words(WordCount **wclist) {
    /* Initialize word count.
       Returns 0 if no errors are encountered
       in the body of this function; 1 otherwise.
    */
    *wclist = NULL;
    return 0;
}

ssize_t len_words(WordCount *wchead) {
    /* Return -1 if any errors are
       encountered in the body of
       this function.
    */
    if (wchead == NULL) {
        return 0;
    }

    size_t len = 0;
    WordCount *wc = wchead;
    while (wc) {
        len++;
        wc = wc->next;
    }
    return len;
}

WordCount *find_word(WordCount *wchead, char *word) {
    /* Return count for word, if it exists */
    WordCount *wc = wchead;
    while (wc) {
        if (strcmp(wc->word, word) == 0) {
            return wc;
        }
        wc = wc->next;
    }
    return NULL;
}

int add_word(WordCount **wclist, char *word) {
    /* If word is present in word_counts list, increment the count.
       Otherwise insert with count 1.
       Returns 0 if no errors are encountered in the body of this function; 1 otherwise.
    */
    WordCount *wc = find_word(*wclist, word);
    if (wc) {
        wc->count++;
        return 0;
    }

    WordCount *new_wc = (WordCount *)malloc(sizeof(WordCount));
    if (new_wc == NULL) {
        fprintf(stderr, "Error: malloc\n");
        return 1;
    }

    new_wc->word = new_string(word);
    if (new_wc->word == NULL) {
        fprintf(stderr, "Error: malloc\n");
        free(new_wc);
        return 1;
    }

    new_wc->count = 1;
    new_wc->next = *wclist;
    *wclist = new_wc;

    return 0;
}

// int wordcntcmp(const WordCount *wc1, WordCount *wc2) {
//     return strcmp(wc1->word, wc2->word);
// }

void fprint_words(WordCount *wchead, FILE *ofile) {
    /* print word counts to a file */
    WordCount *wc;
    for (wc = wchead; wc; wc = wc->next) {
        fprintf(ofile, "%i\t%s\n", wc->count, wc->word);
    }
}

// void wordcount_insert_ordered(WordCount **wclist, WordCount *elem, bool less(const WordCount *, const WordCount *)) {
//     /* Insert word count into the list, ordered accordingly */
//     WordCount *curr = *wclist;
//     WordCount *prev = NULL;

//     while (curr != NULL && less(curr, elem)) {
//         prev = curr;
//         curr = curr->next;
//     }

//     if (prev == NULL) {
//         // 插入链表头部
//         elem->next = *wclist;
//         *wclist = elem;
//     } else {
//         // 插入链表中间或尾部
//         elem->next = curr;
//         prev->next = elem;
//     }
// }

// void wordcount_sort(WordCount **wclist, bool less(const WordCount *, const WordCount *)) {
//     /* Sort the word count list in place */
//     WordCount *result = NULL;
//     WordCount *curr = *wclist;
//     WordCount *next;

//     while (curr != NULL) {
//         next = curr->next;
//         wordcount_insert_ordered(&result, curr, less);
//         curr = next;
//     }

//     *wclist = result;
// }
