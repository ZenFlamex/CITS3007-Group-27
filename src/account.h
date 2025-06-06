// DO NOT SUBMIT THIS FILE
//
// When submitting your project, this file will be overwritten
// by the automated build and test system.
//
// DO NOT EDIT THIS FILE
//
// Since any changes you make will be lost when you submit your project.

#ifndef ACCOUNT_H
#define ACCOUNT_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#define USER_ID_LENGTH 100
#define HASH_LENGTH 128
#define EMAIL_LENGTH 100
#define BIRTHDATE_LENGTH 10
#define IP_SIZE 4

/**
 * An IPv4 address, represented as a 32-bit unsigned integer.
 * */
typedef uint32_t ip4_addr_t;

/**
 * User account structure.
 */
typedef struct {
  int64_t account_id;
  char userid[USER_ID_LENGTH];      // User ID of up to USER_ID_LENGTH chars; null-terminated if less than that
  char password_hash[HASH_LENGTH];  // Encodes details of a hashed password (e.g. hash algorithm, salt, actual hash,
                                    // etc.).
                                    // Is always null terminated and is of length < HASH_LENGTH.
  char email[EMAIL_LENGTH];         // An email address of up to EMAIL_LENGTH chars; null-terminated if less than that
  time_t unban_time;                // Ban the account up until this time (0 = no ban)
  time_t expiration_time;           // Account is only valid until this time (0 = unlimited)
  unsigned int login_count;         // Number of successful auth attempts, default = 0
  unsigned int login_fail_count;    // Number of unsuccessful auth attempts, default = 0
  time_t last_login_time;           // Time of last successful login, default = time 0.
  ip4_addr_t last_ip;               // Last IP connected from, default = 0
  char birthdate[BIRTHDATE_LENGTH]; // Birth date (format: YYYY-MM-DD, default: 0000-00-00)
} account_t;



////
// Account creation

// create an account with specified userid, hash derived from
// specifed password, specified email, and specified birthdate.
// Other fields are set to their default values.
// returns null on error and logs an error message.
account_t *account_create(const char *userid,
                          const char *plaintext_password,
                          const char *email,
                          const char *birthdate);

// free memory and resources used by the account
void account_free(account_t *acc);

////
// Password handling

// check whether supplied password is correct. returns true on success, false on failure
// plaintext_password is the password to check, and should be transmitted over a secure channel.
// acc is the account to check against.
bool account_validate_password(const account_t *acc, const char *plaintext_password);

// set hashed password record derived from new plaintext password.
// returns true on success, false on failure
bool account_update_password(account_t *acc, const char *new_plaintext_password);

////
// Login tracking

// record a successful login. ip must be a valid IPv4 address.
void account_record_login_success(account_t *acc, ip4_addr_t ip);

// record a failed login
void account_record_login_failure(account_t *acc);

////
// Account state checks

// whether account is banned
bool account_is_banned(const account_t *acc);

// whether account is expired
bool account_is_expired(const account_t *acc);

////
// Metadata updates

// set a ban and an expire time. 
void account_set_unban_time(account_t *acc, time_t t);

// set an account expiration time
void account_set_expiration_time(account_t *acc, time_t t);

// set account email address
void account_set_email(account_t *acc, const char *new_email);

// print account information to the specified file descriptor
// (e.g. stdout, stderr, or a log file).
// The account information is printed in a human-readable format.
// returns true on success, false on failure.
// The caller is responsible for ensuring that the file descriptor is valid and writable.
bool account_print_summary(const account_t *acct, int fd);



#endif // ACCOUNT_H
