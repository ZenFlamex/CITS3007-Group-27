#include "account.h"
#include "logging.h"
#include <stdlib.h>
#include <time.h>
#include <string.h>
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

bool account_validate_password(const account_t *acc, const char *plaintext_password)
{
  // remove the contents of this function and replace it with your own code.
  (void)acc;
  (void)plaintext_password;
  return false;
}

/**
 * Sets password memeber in acc to the hash of the new plaintext password
 * 
 * Preconditions:
 * - acc and new_plaintext_password must be non-NULL.
 * - new_plaintext_password must be a valid, null-terminated string.
 * 
 * @param acc A pointer to the account structure.
 * @param new_plaintext_password The plaintext of the password to be hashed
 */
bool account_update_password(account_t *acc, const char *new_plaintext_password)
{
  //NOTE THE SALT AND HASH IN THIS FUNCTION ARE TEMPORARY AND NEED TO BE CHANGED!
  char *salt[HASH_LENGTH] = "TEMP SALT";
  char *password_hash[HASH_LENGTH] = TEMP_HASH_FUNCTION(new_plaintext_password, salt);
  char *combined_salt_hash[HASH_LENGTH];

  strcat(combined_salt_hash,password_hash);
  strcpy(acc->password_hash,combined_salt_hash);

  return true;
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

bool account_print_summary(const account_t *acct, int fd)
{
  // remove the contents of this function and replace it with your own code.
  (void)acct;
  (void)fd;
  return false;
}
