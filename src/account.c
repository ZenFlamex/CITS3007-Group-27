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
#include <crypt.h>
#include <arpa/inet.h>
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
account_t *acc = malloc(sizeof(account_t));
if (acc == NULL){
log_message(LOG_ERROR, "failed to allocate memory for account");
return NULL;
}

// Set default & supplied values
acc->account_id = 0;
if (strlen(userid) < USER_ID_LENGTH){
strcpy(acc->userid,*userid);
} else {
log_message(LOG_ERROR,"invalid userID. too long");
}
account_update_password(acc,plaintext_password);
account_set_email(acc,email);
acc->unban_time = 0;
acc->expiration_time = 0;
acc->login_count = 0;
acc->login_fail_count = 0;
acc->last_login_time = 0;
acc->last_ip = 0;

// verifying birthday format
for (int i = 0; i < 10; i++){
if ((i == 4 || i == 7)&& (birthdate[i] != '-')){
log_message(LOG_ERROR,"invalid birthday format");
account_free(acc);
return NULL;
}
else if (birthdate[i] > '9' || birthdate[i] < '0'){
log_message(LOG_ERROR,"invalid birthday format");
account_free(acc);
return NULL;
}
}

// verifying birthdate hasn't happened yet
time_t current_time_std = time(NULL);
struct tm *current_time_struct = localtime(&current_time_std);

int Birthday_year  = (birthdate[0]-'0') *1000 + (birthdate[1]-'0') * 100 + (birthdate[2]-'0') * 10 + (birthdate[3]-'0');
int Birthday_month = (birthdate[5]-'0') *  10 + (birthdate[6]-'0');
int Birthday_day   = (birthdate[8]-'0') *  10 + (birthdate[9]-'0');

if (current_time_struct->tm_year < Birthday_year){
log_message(LOG_ERROR,"invalid birthday (day has not happened)");
account_free(acc);
return NULL;
}

else if (current_time_struct->tm_year == Birthday_year){
if (current_time_struct->tm_mon < Birthday_month){
log_message(LOG_ERROR,"invalid birthday (day has not happened)");
account_free(acc);
return NULL;

}
else if (current_time_struct->tm_mon == Birthday_month){
if (current_time_struct <= Birthday_day){
log_message(LOG_ERROR,"invalid birthday (day has not happened)");
account_free(acc);
return NULL;
}
}
}

strcpy(acc->birthdate,*birthdate);

return acc;
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
  // Defensive: ensure password length is within a safe bound
  size_t pwd_len = strnlen(plaintext_password, 1024); // prevent accidental infinite string
  if (pwd_len >= 1024) {
      log_message(STDERR_FILENO, "account_validate_password: password too long or not null-terminated");
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

  time_t now = time(NULL); 
  acc->last_login_time = now; //it sets the account's last_login_time to current timestamp
  acc->last_ip = ip; 

  // Defensive: avoid overflow
  if (acc->login_count < UINT_MAX) { 
      acc->login_count++; //before incrementing it
  }
  acc->login_fail_count = 0; //successful login resets the count of failed attempts
  // Format human-readable time
  char timebuf[64]; //timebuf is a string containing the formatted current time, "2025-04-23 12:34:56"
  strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", localtime(&now)); 
  // Format IP address
  char ipbuf[INET_ADDRSTRLEN];
  struct in_addr addr = { .s_addr = ip }; //struct in_addr is a struct used to represent an IPv4 address
  inet_ntop(AF_INET, &addr, ipbuf, sizeof(ipbuf)); 
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
  if (acc->login_fail_count < UINT_MAX) { 
      acc->login_fail_count++;
  }

  time_t now = time(NULL); 

  char timebuf[64];
  strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", localtime(&now)); //This formats the current time into a human-readable string, stored in timebuf.
  // format last known IP (if available)
  char ipbuf[INET_ADDRSTRLEN] = "unknown"; 
  struct in_addr addr = { .s_addr = acc->last_ip };
  inet_ntop(AF_INET, &addr, ipbuf, sizeof(ipbuf)); //it uses the inet_ntop() function to convert a binary IPv4 address into a printable string format, like "127.0.0.1"
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
 * Checks if the provided email is valid
 * 
 * Preconditions:
 * - email must not be NULL.
 * 
 * @param email A pointer to a string
 * @return true if email is printable ASKII chars and under EMAIL_LENGTH
 */
bool email_is_valid(const char *email)
{
  int email_length = strlen(email);

  if (email_length >= EMAIL_LENGTH)
  {
    return false;
  }
  for (int i = 0; i < email_length; i++)
  {
    // checks if each charicter is valid
    if ((email[i] < 33) || (email[i] > 126))
    {
      return false;
    }
  }
  return true;
}

/**
 * Sets email memeber in acc to the new email
 * 
 * Preconditions:
 * - acc and new_email must be non-NULL.
 * - new_email must be a valid, null-terminated string.
 * 
 * @param acc A pointer to the account structure.
 * @param email A pointer to a string that will become the new email
 */
void account_set_email(account_t *acc, const char *new_email)
{
  if (email_is_valid(new_email))
  {
    strcpy(acc->email,new_email);
  }
  return;
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
