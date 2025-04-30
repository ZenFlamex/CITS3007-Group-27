// DO NOT SUBMIT THIS FILE
//
// When submitting your project, this file will be overwritten
// by the automated build and test system.
//
// You can replace these stub implementations with your own code,
// if you wish.

#include "logging.h"
#include "db.h"

#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>


/**
 * Abort immediately for unrecoverable errors /
 * invalid program state.
 * 
 * Arguments:
 * - msg: message to log before aborting
 * 
 * This function should not return.
 */
void panic(const char *msg) {
  fprintf(stderr, "PANIC: %s\n", msg);
  abort();
}

// Global mutex for logging
// This mutex is used to ensure that log messages are printed in a thread-safe manner.
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

void log_message(log_level_t level, const char *fmt, ...) {
  pthread_mutex_lock(&log_mutex);

  va_list args;
  va_start(args, fmt);
  switch (level) {
    case LOG_DEBUG:
      fprintf(stderr, "DEBUG: ");
      break;
    case LOG_INFO:
      fprintf(stdout, "INFO: ");
      break;
    case LOG_WARN:
      fprintf(stderr, "WARNING: ");
      break;
    case LOG_ERROR:
      fprintf(stderr, "ERROR: ");
      break;
    default:
      panic("Invalid log level");
      break;
  }
  vfprintf(stderr, fmt, args);
  fprintf(stderr, "\n");  // newline, optional
  va_end(args);

  pthread_mutex_unlock(&log_mutex);
}


#include <string.h>
#include "db.h"
#include "logging.h"
#include <stdbool.h>
#include <stdlib.h>

bool account_lookup_by_userid(const char *userid, account_t *acc) {
    if (!userid || !acc) {
        panic("Invalid arguments to account_lookup_by_userid");
    }

    memset(acc, 0, sizeof(account_t));  // 清空结构体

    if (strncmp(userid, "bob", USER_ID_LENGTH) == 0) {
        strcpy(acc->userid, "bob");
        strcpy(acc->email, "bob@example.com");
        strcpy(acc->birthdate, "1990-01-01");
        return true;
    }

    if (strncmp(userid, "bob_banned", USER_ID_LENGTH) == 0) {
        strcpy(acc->userid, "bob_banned");
        strcpy(acc->email, "banned@example.com");
        strcpy(acc->birthdate, "1990-01-01");
        return true;
    }

    if (strncmp(userid, "bob_expired", USER_ID_LENGTH) == 0) {
        strcpy(acc->userid, "bob_expired");
        strcpy(acc->email, "expired@example.com");
        strcpy(acc->birthdate, "1990-01-01");
        return true;
    }

    // 其他用户一律返回找不到
    return false;
}
