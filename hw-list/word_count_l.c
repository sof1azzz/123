/*
 * Implementation of the word_count interface using Pintos lists.
 *
 * You may modify this file, and are expected to modify it.
 */

/*
 * Copyright © 2021 University of California, Berkeley
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef PINTOS_LIST
#error "PINTOS_LIST must be #define'd when compiling word_count_l.c"
#endif

#include "word_count.h"

void init_words(word_count_list_t *wclist) { /* TODO */
  list_init(wclist);
}

size_t len_words(word_count_list_t *wclist) {
  return list_size(wclist);
}

word_count_t* find_word(word_count_list_t* wclist, char* word) {
  /* TODO */
  struct list_elem *e;

  for (e = list_begin(wclist); e != list_end(wclist); e = list_next(e)) {
    word_count_t *foo = list_entry(e, word_count_t, elem);
    if (strcmp(foo->word, word) == 0) {
      return foo;
    }
  }
  /* TODO */

  return NULL;
}

word_count_t* add_word(word_count_list_t* wclist, char* word) {
  /* TODO */
  word_count_t *temp = find_word(wclist, word);

  if (temp) {
    temp->count++;
    return temp;
  } else {
    word_count_t *new_node = malloc(sizeof(word_count_t));
    if (!new_node) {
      perror("malloc new node");
      return NULL;
    }

    new_node->word = strdup(word);
    if (!new_node->word) {
      perror("malloc word");
      return NULL;
    }
    new_node->count = 1;

    list_push_front(wclist, &new_node->elem);
    return new_node;
  }
}

void fprint_words(word_count_list_t* wclist, FILE* outfile) {
  /* TODO */
  /* Please follow this format: fprintf(<file>, "%i\t%s\n", <count>, <word>); */
  struct list_elem *e;

  for (e = list_begin(wclist); e != list_end(wclist); e = list_next(e)) {
    word_count_t *foo = list_entry(e, word_count_t, elem);
    fprintf(outfile, "%i\t%s\n", foo->count, foo->word);
  }
}

static bool less_list(const struct list_elem* ewc1, const struct list_elem* ewc2, void* aux) {
  /* TODO */
  word_count_t *w1 = list_entry(ewc1, word_count_t, elem);
  word_count_t *w2 = list_entry(ewc2, word_count_t, elem);
  bool (*less)(const word_count_t *, const word_count_t *) = aux;
  return less(w1, w2);
}

void wordcount_sort(word_count_list_t* wclist,
                    bool less(const word_count_t*, const word_count_t*)) {
  list_sort(wclist, less_list, less);
}
