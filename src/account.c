#include "account.h"
#include <stdlib.h>
#include <time.h>
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

bool account_validate_password(const account_t *acc, const char *plaintext_password)
{
  // remove the contents of this function and replace it with your own code.
  (void)acc;
  (void)plaintext_password;
  return false;
}

bool account_update_password(account_t *acc, const char *new_plaintext_password)
{
  // remove the contents of this function and replace it with your own code.
  (void)acc;
  (void)new_plaintext_password;
  return false;
}

void account_record_login_success(account_t *acc, ip4_addr_t ip)
{
  // remove the contents of this function and replace it with your own code.
  (void)acc;
  (void)ip;
}

void account_record_login_failure(account_t *acc)
{
  // remove the contents of this function and replace it with your own code.
  (void)acc;
}

/**
 * Check if an account is currently banned.
 *
 * An account is considered banned if its unban_time is set to a future time.
 *
 * @param acc The account to check
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
 * @param acc The account to check
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
 * @param acc A pointer to the account structure.
 * @param t The time at which the account should expire.
 */
void account_set_expiration_time(account_t *acc, time_t t)
{
  acc->expiration_time = t;
}

void account_set_email(account_t *acc, const char *new_email)
{
  // remove the contents of this function and replace it with your own code.
  (void)acc;
  (void)new_email;
}

bool account_print_summary(const account_t *acct, int fd)
{
  // remove the contents of this function and replace it with your own code.
  (void)acct;
  (void)fd;
  return false;
}
