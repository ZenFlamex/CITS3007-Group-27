#define _GNU_SOURCE
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <ctype.h>
#include <unistd.h>
#include "account.h"
#include "logging.h"
#include <limits.h>
#include <netinet/in.h>  // For IP formatting
#include <arpa/inet.h>   // For inet_ntop
#include <sodium.h>
/**
 * Create a new account with the specified parameters.
 *
 * This function initializes a new dynamically allocated account structure
 * with the given user ID, hash information derived from the specified plaintext password, email address,
 * and birthdate. Other fields are set to their default values.
 *
 * On success, returns a pointer to the newly created account structure.
 * On error, returns NULL and logs an error message.
 */
 account_t *account_create(const char *userid, const char *plaintext_password,
  const char *email, const char *birthdate)
{
// remove the contents of this function and replace it with your own code.
(void)userid;
(void)plaintext_password;
(void)email;
(void)birthdate;

return NULL;
}


void account_free(account_t *acc)
{
  free(acc);
}

bool account_validate_password(const account_t *acc, const char *plaintext_password) {
  if (!acc || !plaintext_password) {
      log_message(STDERR_FILENO, "account_validate_password: NULL input");
      return false;
  }

  if (acc->password_hash[0] == '\0') {
      log_message(STDERR_FILENO, "account_validate_password: no stored password hash");
      return false;
  }

  size_t pwd_len = strnlen(plaintext_password, 1024);
  if (pwd_len >= 1024) {
      log_message(STDERR_FILENO, "account_validate_password: password too long or not null-terminated");
      return false;
  }

  if (pwd_len < 8) {
      log_message(STDERR_FILENO, "Password too short");
      return false;
  }

  int result = crypto_pwhash_str_verify(acc->password_hash, plaintext_password, pwd_len);
  if (result == 0) {
      return true;
  } else if (result == -1) {
      log_message(STDERR_FILENO, "account_validate_password: invalid password");
  } else {
      log_message(STDERR_FILENO, "account_validate_password: unexpected libsodium error");
  }
  return false;
}

bool account_update_password(account_t *acc, const char *new_plaintext_password) {
  if (!acc || !new_plaintext_password) return false;

  // Hash the password using libsodium's recommended Argon2id
  if (crypto_pwhash_str(
          acc->password_hash,                // output
          new_plaintext_password,            // password
          strlen(new_plaintext_password),    // password length
          crypto_pwhash_OPSLIMIT_INTERACTIVE,
          crypto_pwhash_MEMLIMIT_INTERACTIVE
      ) != 0) {
      log_message(STDERR_FILENO, "account_update_password: crypto_pwhash_str failed");
      return false;
  }

  return true;
}

void account_record_login_success(account_t *acc, ip4_addr_t ip) {
  if (!acc) return; //this is a null pointer check

  time_t now = time(NULL); //time(NULL) returns current time, it stores this into now, variable of type time_t
  acc->last_login_time = now; //it sets the account's last_login_time to current timestamp
  acc->last_ip = ip; //ip is passed into function (type ip4_addr_t)

  // Defensive: avoid overflow
  if (acc->login_count < UINT_MAX) { // check whether the login_count is less than the maximum value the unsigned int can hold
      acc->login_count++; //before incrementing it
  }
  acc->login_fail_count = 0; //successful login resets the count of failed attempts
  // Format human-readable time
  char timebuf[64]; //timebuf is a string containing the formatted current time, "2025-04-23 12:34:56"
  strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", localtime(&now)); 
  // Format IP address
  char ipbuf[INET_ADDRSTRLEN];
  struct in_addr addr = { .s_addr = ip }; //struct in_addr is a struct used to represent an IPv4 address
  inet_ntop(AF_INET, &addr, ipbuf, sizeof(ipbuf)); //converts an IPv4 address from binary to a readable string
  // Log the success event with full context
  log_message(STDERR_FILENO,
      "Login success: user=%s | time=%s | ip=%s | login_count=%u",
      acc->userid, timebuf, ipbuf, acc->login_count
  );
}

void account_record_login_failure(account_t *acc) {
    if (!acc) return; // Safety check for null pointer

    acc->login_count = 0; // Reset login count due to failure
    // Defensive: prevent overflow
    if (acc->login_fail_count < UINT_MAX) { //UINT_MAX is defined in <limits.h> and represents the maximum value a unsigned int can store
        acc->login_fail_count++;
    }
    time_t now = time(NULL); 

    char timebuf[64];
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", localtime(&now)); //Formats the current time into a human-readable string, stored in timebuf.
    // format last known IP (if available)
    char ipbuf[INET_ADDRSTRLEN] = "unknown"; 
    struct in_addr addr = { .s_addr = acc->last_ip };
    inet_ntop(AF_INET, &addr, ipbuf, sizeof(ipbuf)); 
    // warning if approaching UINT_MAX
    if (acc->login_fail_count > UINT_MAX - 10) { //checks if the login_fail_count is getting dangerously close to its UINT_MAX.
        log_message(STDERR_FILENO, //if so, it logs a warning to alert the system
            "Warning: login_fail_count nearing overflow for user %s (fail count = %u)",
            acc->userid, acc->login_fail_count);
    }
    // Log failure
    log_message(STDERR_FILENO, //STDERR_FILENO is a file descriptor for standard error output (typically value 2)
        "Login failure: user=%s | time=%s | ip=%s | fail_count=%u", 
        acc->userid, timebuf, ipbuf, acc->login_fail_count); //timebuf is a string containing the formatted current time, like "2025-04-23 12:34:56"
}

/**
 * Check if an account is currently banned.
 *
 * An account is considered banned if its unban_time is set to a future time.
 *
 * @param acc The account to check (must not be NULL).
 * @return true if the account is banned, false otherwise.
 */
bool account_is_banned(const account_t *acc)
{
  if (acc->unban_time == 0)
  {
    return false;
  }

  time_t current_time = time(NULL);

  return current_time < acc->unban_time;
}

/**
 * Check if an account is expired.
 *
 * An account is considered expired if the current time is at or after its expiration_time.
 *
 * @param acc The account to check (must not be NULL).
 * @return true if the account is expired, false otherwise.
 */
bool account_is_expired(const account_t *acc)
{
  // If expiration_time is 0, the account never expires
  if (acc->expiration_time == 0)
  {
    return false;
  }

  time_t current_time = time(NULL);

  return current_time >= acc->expiration_time;
}

/**
 * Set the unban time for an account.
 *
 * Preconditions:
 * - acc must not be NULL.
 *
 * @param acc A pointer to the account structure.
 * @param t The time at which the ban should be lifted.
 */
void account_set_unban_time(account_t *acc, time_t t)
{
  acc->unban_time = t;
}

/**
 * Set the expiration time for an account.
 *
 * Preconditions:
 * - acc must not be NULL.
 *
 * @param acc A pointer to the account structure.
 * @param t The time at which the account should expire.
 */
void account_set_expiration_time(account_t *acc, time_t t)
{
  acc->expiration_time = t;
}

/**
 * Sets email memeber in acc to the new email
 * 
 * Preconditions:
 * - acc and new_email must be non-NULL.
 * - new_email must be a valid, null-terminated string.
 **/
 void account_set_email(account_t *acc, const char *new_email)
{
  // remove the contents of this function and replace it with your own code.
  (void)acc;
  (void)new_email;
}

bool account_print_summary(const account_t *acct, int fd) {
  if (!acct || fd < 0) return false; //!acct: is the acct pointer NULL? || fd < 0: is the file descriptor invalid?

  int written = dprintf(fd,
      "User ID: %s\n"
      "Email: %s\n"
      "Birthdate: %s\n"
      "Login count: %u\n"
      "Login failures: %u\n"
      "Last login time: %ld\n"
      "Last IP: %u\n"
      "Banned until: %ld\n"
      "Expires at: %ld\n",
      acct->userid,
      acct->email,
      acct->birthdate,
      acct->login_count,
      acct->login_fail_count,
      acct->last_login_time,
      acct->last_ip,
      acct->unban_time,
      acct->expiration_time
  );

  return written > 0;
}

