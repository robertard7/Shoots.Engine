#ifndef SHOOTS_ENGINE_ALWAYS_ASSERT_H
#define SHOOTS_ENGINE_ALWAYS_ASSERT_H

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

static inline void shoots_test_assert_fail(const char *expression,
                                           const char *file,
                                           int line) {
  fprintf(stderr,
          "assertion failed: %s (%s:%d)\n",
          expression != NULL ? expression : "(null)",
          file != NULL ? file : "(unknown)",
          line);
  abort();
}

#undef assert
#define assert(expression) \
  ((expression) ? (void)0 : shoots_test_assert_fail(#expression, __FILE__, __LINE__))

#endif
