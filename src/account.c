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
#include <netinet/in.h> // For IP formatting
#include <arpa/inet.h>  // For inet_ntop
#include <sodium.h>
#include "banned.h"

/**
 * Create a new account with the specified parameters.
 *
 *
 * Creates a new user account with the given parameters (and defaults for any other fields).
 * The password is hashed securely, and the resulting account is dynamically allocated.
 * Validates birthdate format and email basic requirements.
 *
 * On success, returns a pointer to the newly created account structure.
 * On error, returns NULL and logs an error message.
 */
account_t *account_create(const char *userid, const char *plaintext_password,
                          const char *email, const char *birthdate)
{
  // Allocate memory for the new account
  account_t *acc = malloc(sizeof(account_t));
  if (acc == NULL)
  {
    log_message(LOG_ERROR, "Failed to allocate memory for account");
    return NULL;
  }

  // Initialize all fields to zero
  memset(acc, 0, sizeof(account_t));

  // Copy userid if it fits in the buffer
  if (strlen(userid) < USER_ID_LENGTH)
  { // Leave space for null terminator
    strncpy(acc->userid, userid, USER_ID_LENGTH - 1);
    acc->userid[USER_ID_LENGTH - 1] = '\0'; // Ensure null termination
  }
  else
  {
    log_message(LOG_ERROR, "Invalid userID: too long");
    account_free(acc);
    return NULL;
  }

  // Validate and copy email - Implement email validation as specified
  // Email should consist only of ASCII printable characters and no spaces
  size_t email_len = strlen(email);
  if (email_len < EMAIL_LENGTH)
  { // Check if email fits
    // Check for printable ASCII and no spaces
    bool valid = true;
    for (size_t i = 0; i < email_len; i++)
    {
      if (!isprint((unsigned char)email[i]) || isspace((unsigned char)email[i]))
      {
        valid = false;
        break;
      }
    }

    if (valid)
    {
      strncpy(acc->email, email, EMAIL_LENGTH - 1);
      acc->email[EMAIL_LENGTH - 1] = '\0'; // Ensure null termination
    }
    else
    {
      log_message(LOG_ERROR, "Invalid email: contains non-printable characters or spaces");
      account_free(acc);
      return NULL;
    }
  }
  else
  {
    log_message(LOG_ERROR, "Invalid email: too long");
    account_free(acc);
    return NULL;
  }

  // Validate birthdate format (YYYY-MM-DD)
  if (strlen(birthdate) != 10)
  {
    log_message(LOG_ERROR, "Invalid birthdate format: incorrect length");
    account_free(acc);
    return NULL;
  }

  // Check hyphens are in the right positions (4 and 7)
  if (birthdate[4] != '-' || birthdate[7] != '-')
  {
    log_message(LOG_ERROR, "Invalid birthdate format: hyphens not in correct positions");
    account_free(acc);
    return NULL;
  }

  // Check all other characters are digits
  for (int i = 0; i < 10; i++)
  {
    if (i != 4 && i != 7)
    { // Skip the hyphen positions
      if (!isdigit((unsigned char)birthdate[i]))
      {
        log_message(LOG_ERROR, "Invalid birthdate format: non-digit character");
        account_free(acc);
        return NULL;
      }
    }
  }

  // Extract year, month, and day values
  int year = (birthdate[0] - '0') * 1000 + (birthdate[1] - '0') * 100 +
             (birthdate[2] - '0') * 10 + (birthdate[3] - '0');
  int month = (birthdate[5] - '0') * 10 + (birthdate[6] - '0');
  int day = (birthdate[8] - '0') * 10 + (birthdate[9] - '0');

  // Validate month is between 1 and 12
  if (month < 1 || month > 12)
  {
    log_message(LOG_ERROR, "Invalid birthdate: month out of range");
    account_free(acc);
    return NULL;
  }

  // Validate day based on month
  int max_days = 31; // Most months have 31 days
  if (month == 4 || month == 6 || month == 9 || month == 11)
  {
    max_days = 30; // April, June, September, November have 30 days
  }
  else if (month == 2)
  {
    // February has 28 days, 29 in leap years
    if ((year % 4 == 0 && year % 100 != 0) || (year % 400 == 0))
    {
      max_days = 29; // Leap year
    }
    else
    {
      max_days = 28; // Non-leap year
    }
  }

  if (day < 1 || day > max_days)
  {
    log_message(LOG_ERROR, "Invalid birthdate: day out of range for month");
    account_free(acc);
    return NULL;
  }

  // If birthdate is valid, copy it using memcpy (no null terminator needed)
  memcpy(acc->birthdate, birthdate, BIRTHDATE_LENGTH);

  // Set default values for account fields
  acc->account_id = 0;
  acc->unban_time = 0;
  acc->expiration_time = 0;
  acc->login_count = 0;
  acc->login_fail_count = 0;
  acc->last_login_time = 0;
  acc->last_ip = 0;

  // Hash password and update account
  if (!account_update_password(acc, plaintext_password))
  {
    log_message(LOG_ERROR, "Failed to set password");
    account_free(acc);
    return NULL;
  }

  return acc;
}

/**
 * Releases memory associated with an account.
 *
 *
 * This function frees all memory allocated for the account structure.
 * It safely handles NULL pointers.
 */
void account_free(account_t *acc)
{
  free(acc);
}

/**
 * Checks if the provided email is valid
 *
 *
 * @param email A pointer to a string
 * @return true if email is printable ASCII chars and under EMAIL_LENGTH
 */
bool email_is_valid(const char *email)
{
  size_t email_length = strlen(email);

  if (email_length >= EMAIL_LENGTH)
  {
    return false;
  }
  for (size_t i = 0; i < email_length; i++)
  {
    // checks if each charicter is valid
    if (!isprint((unsigned char)email[i]) || isspace((unsigned char)email[i]))
    {
      return false;
    }
  }
  return true;
}

/**
 * Sets email memeber in acc to the new email
 *
 *
 * @param acc A pointer to the account structure.
 * @param email A pointer to a string that will become the new email
 */
void account_set_email(account_t *acc, const char *new_email)
{
  if (email_is_valid(new_email))
  {
    strncpy(acc->email, new_email, EMAIL_LENGTH - 1);
    acc->email[EMAIL_LENGTH - 1] = '\0'; // Ensure null termination
  }
  return;
}

/**
 * Validates a plaintext password against the stored hash.
 *
 *
 * @param acc A pointer to the account structure containing the password hash.
 * @param plaintext_password The plaintext password to validate.
 * @return true if the password matches the stored hash, false otherwise.
 */
bool account_validate_password(const account_t *acc, const char *plaintext_password)
{
  // Verify the password using libsodium
  int result = crypto_pwhash_str_verify(acc->password_hash, plaintext_password, strlen(plaintext_password));

  if (result == 0)
  {
    return true; // Password matches
  }
  else
  {
    log_message(LOG_ERROR, "Password validation failed");
    return false; // Password doesn't match
  }
}

/**
 * Updates an account's password.
 *
 *
 * @param acc A pointer to the account structure.
 * @param new_plaintext_password The new password to set.
 * @return true if the password was successfully updated, false otherwise.
 */
bool account_update_password(account_t *acc, const char *new_plaintext_password)
{
  // Define constants for password policy
  const size_t MIN_PASSWORD_LENGTH = 8;

  size_t pwd_len = strlen(new_plaintext_password);

  // Enforce minimum length
  if (pwd_len < MIN_PASSWORD_LENGTH)
  {
    log_message(LOG_ERROR, "Password too short (minimum 8 characters required)");
    return false;
  }

  // Enforce character diversity
  bool has_upper = false, has_lower = false, has_digit = false, has_special = false;
  for (size_t i = 0; i < pwd_len; ++i)
  {
    unsigned char c = (unsigned char)new_plaintext_password[i];
    if (isupper(c))
      has_upper = true;
    else if (islower(c))
      has_lower = true;
    else if (isdigit(c))
      has_digit = true;
    else if (ispunct(c))
      has_special = true;
  }

  if (!has_upper || !has_lower || !has_digit || !has_special)
  {
    log_message(LOG_ERROR, "Password must include uppercase, lowercase, digit, and special characters");
    return false;
  }

  // Hash the password using libsodium's recommended Argon2id
  if (crypto_pwhash_str(
          acc->password_hash,
          new_plaintext_password,
          pwd_len,
          crypto_pwhash_OPSLIMIT_INTERACTIVE,
          crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0)
  {
    log_message(LOG_ERROR, "Failed to hash password");
    return false;
  }

  return true;
}

/**
 * Records a successful login.
 *
 *
 * @param acc A pointer to the account structure.
 * @param ip The IP address from which the login occurred.
 */
void account_record_login_success(account_t *acc, ip4_addr_t ip)
{
  // Update login time and IP
  acc->last_login_time = time(NULL);
  acc->last_ip = ip;

  // Increment login count with overflow protection
  if (acc->login_count < UINT_MAX)
  {
    acc->login_count++;
  }

  // Reset failed login counter
  acc->login_fail_count = 0;

  // Log the event (using proper log level)
  char timebuf[64];
  strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", localtime(&acc->last_login_time));

  char ipbuf[INET_ADDRSTRLEN];
  struct in_addr addr = {.s_addr = ip};
  inet_ntop(AF_INET, &addr, ipbuf, sizeof(ipbuf));

  log_message(LOG_INFO,
              "Login success: user=%s | time=%s | ip=%s | login_count=%u",
              acc->userid, timebuf, ipbuf, acc->login_count);
}

/**
 * Records a failed login attempt.
 *
 *
 * @param acc A pointer to the account structure.
 */
void account_record_login_failure(account_t *acc)
{
  // Reset login counter
  acc->login_count = 0;

  // Increment failed login count with overflow protection
  if (acc->login_fail_count < UINT_MAX)
  {
    acc->login_fail_count++;
  }

  // Get current time
  time_t now = time(NULL);

  // Log the failure
  char timebuf[64];
  strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", localtime(&now));

  // Format last known IP if available
  char ipbuf[INET_ADDRSTRLEN];
  if (acc->last_ip != 0)
  {
    struct in_addr addr = {.s_addr = acc->last_ip};
    inet_ntop(AF_INET, &addr, ipbuf, sizeof(ipbuf));
  }
  else
  {
    strncpy(ipbuf, "unknown", sizeof(ipbuf) - 1);
    ipbuf[sizeof(ipbuf) - 1] = '\0';
  }

  // Warning if approaching overflow
  if (acc->login_fail_count > UINT_MAX - 10)
  {
    log_message(LOG_WARN,
                "Warning: login_fail_count nearing overflow for user %s (fail count = %u)",
                acc->userid, acc->login_fail_count);
  }

  log_message(LOG_WARN,
              "Login failure: user=%s | time=%s | ip=%s | fail_count=%u",
              acc->userid, timebuf, ipbuf, acc->login_fail_count);
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
 *
 * @param acc A pointer to the account structure.
 * @param t The time at which the account should expire.
 */
void account_set_expiration_time(account_t *acc, time_t t)
{
  acc->expiration_time = t;
}

/**
 * Prints a human-readable summary of an account to the specified file descriptor.
 *
 *
 * @param acct The account structure to summarize.
 * @param fd The file descriptor to write to.
 * @return true if the write succeeds, false otherwise.
 */
bool account_print_summary(const account_t *acct, int fd)
{
  // Format timestamps as human-readable strings
  char last_login_time[64] = "Never";
  if (acct->last_login_time > 0)
  {
    strftime(last_login_time, sizeof(last_login_time), "%Y-%m-%d %H:%M:%S",
             localtime(&acct->last_login_time));
  }

  char unban_time[64] = "Not banned";
  if (acct->unban_time > 0)
  {
    strftime(unban_time, sizeof(unban_time), "%Y-%m-%d %H:%M:%S",
             localtime(&acct->unban_time));
  }

  char expiration_time[64] = "Never";
  if (acct->expiration_time > 0)
  {
    strftime(expiration_time, sizeof(expiration_time), "%Y-%m-%d %H:%M:%S",
             localtime(&acct->expiration_time));
  }

  // Format IP address as human-readable string
  char ip_str[INET_ADDRSTRLEN] = "None";
  if (acct->last_ip != 0)
  {
    struct in_addr addr = {.s_addr = acct->last_ip};
    inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));
  }

  // Write the formatted summary to the file descriptor
  int written = dprintf(fd,
                        "===== Account Summary =====\n"
                        "User ID: %s\n"
                        "Email: %s\n"
                        "Birthdate: %s\n"
                        "Login count: %u\n"
                        "Login failures: %u\n"
                        "Last login: %s\n"
                        "Last IP: %s\n"
                        "Ban status: %s\n"
                        "Expiration: %s\n"
                        "==========================\n",
                        acct->userid,
                        acct->email,
                        acct->birthdate,
                        acct->login_count,
                        acct->login_fail_count,
                        last_login_time,
                        ip_str,
                        unban_time,
                        expiration_time);

  if (written <= 0)
  {
    log_message(LOG_ERROR, "Failed to write account summary to file descriptor");
    return false;
  }

  return true;
}