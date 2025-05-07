#define CITS3007_PERMISSIVE

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>  // For inet_addr()
#include <netinet/in.h> // For IP formatting

#include "account.h"

#define ARR_SIZE(arr)(sizeof(arr) / sizeof((arr)[0]))

/**
 * Helper function to create a dummy account for testing
 */
static account_t create_dummy_account(void)
{
    account_t acc = { 0};
  acc.unban_time = 0;
  acc.expiration_time = 0;
  return acc;
}

/**
 * Test suite for the account structure and related functions.
 * As per contract:
 * - String arguments are assumed to be null-terminated
 * - No null pointer validation is required in functions
 * - Parameter validation is the caller's responsibility
 */
#suite account_suite

/* 
 * Account Create Test Cases
 * ------------------------
 * Tests for account creation functions
 */
#tcase account_create_test_case

/**
 * Test that account_create successfully creates an account with valid parameters
 * TODO: This test will fail until account_create is implemented
 */
#test test_account_create_works
// TODO: Implement account_create function to pass this test
ck_assert_msg(0, "account_create not yet implemented");

/**
 * Test that account_create returns NULL for invalid email (contains spaces)
 * TODO: This test will fail until account_create is implemented
 */
#test test_account_create_invalid_email
// TODO: Implement account_create function to pass this test
ck_assert_msg(0, "account_create not yet implemented");

/**
 * Test that account_create returns NULL for invalid birthdate format
 * TODO: This test will fail until account_create is implemented
 */
#test test_account_create_invalid_birthdate
// TODO: Implement account_create function to pass this test
ck_assert_msg(0, "account_create not yet implemented");

/* 
 * Account Free Test Cases
 * ---------------------
 * Tests for account_free function
 */
#tcase account_free_test_case

/**
 * Test that account_free works with NULL (contract states account_free can accept NULL)
 */
#test test_account_free_with_null
account_free(NULL);
ck_assert(true);

/* 
 * Account Email Test Cases
 * ----------------------
 * Tests for email-related functions
 */
#tcase account_email_test_case

/**
 * Test setting a new email address for an account
 * TODO: This test will fail until account_set_email is implemented
 */
#test test_account_set_email
// TODO: Implement account_set_email function to pass this test
ck_assert_msg(0, "account_set_email not yet implemented");

/* 
 * Ban-related Test Cases
 * ---------------------
 * Tests for banning and checking ban status
 */
#tcase account_ban_test_case

/**
 * Test setting and checking account ban times
 * These functions are already implemented and should pass
 */
#test test_account_ban_times
// Test account_set_unban_time() and account_is_banned()
account_t acc = create_dummy_account();
time_t now = time(NULL);
if (now == (time_t)(-1)) {
  ck_assert_msg(0, "Failed to get current time");
}

// Test case 1: Ban time in the future
account_set_unban_time(& acc, now + 10);
ck_assert_int_eq(account_is_banned(& acc), 1); // Should be banned because unban_time is in the future

// Test case 2: Ban time in the past
account_set_unban_time(& acc, now - 10);
ck_assert_int_eq(account_is_banned(& acc), 0); // Should not be banned because unban_time is in the past

// Test case 3: No ban (unban_time = 0)
account_set_unban_time(& acc, 0);
ck_assert_int_eq(account_is_banned(& acc), 0); // Should not be banned because unban_time is 0

/* 
 * Expiration-related Test Cases
 * ---------------------------
 * Tests for expiration and checking expiration status
 */
#tcase account_expiration_test_case

/**
 * Test setting and checking account expiration times
 * These functions are already implemented and should pass
 */
#test test_account_expiration_times
// Test account_set_expiration_time() and account_is_expired()
account_t acc = create_dummy_account();
time_t now = time(NULL);
if (now == (time_t)(-1)) {
  ck_assert_msg(0, "Failed to get current time");
}

// Test case 1: Expiration time in the past
account_set_expiration_time(& acc, now - 10);
ck_assert_int_eq(account_is_expired(& acc), 1); // Should be expired because expiration_time is in the past

// Test case 2: Expiration time in the future
account_set_expiration_time(& acc, now + 10);
ck_assert_int_eq(account_is_expired(& acc), 0); // Should not be expired because expiration_time is in the future

// Test case 3: Expiration time right now
account_set_expiration_time(& acc, now);
ck_assert_int_eq(account_is_expired(& acc), 1); // Should be expired immediately at expiration_time

// Test case 4: No expiration (expiration_time = 0)
account_set_expiration_time(& acc, 0);
ck_assert_int_eq(account_is_expired(& acc), 0); // Should not be expired because expiration_time is 0

/* 
 * Account Login Recording Test Cases
 * -------------------------------
 * Tests for login tracking functions
 */
#tcase account_login_record_test_case

/**
 * Test recording a successful login
 */
#test test_account_record_login_success
account_t acc = create_dummy_account();
ip4_addr_t ip = inet_addr("127.0.0.1");
account_record_login_success(& acc, ip);
ck_assert_int_eq(acc.login_count, 1);
ck_assert_int_eq(acc.login_fail_count, 0);
ck_assert_int_eq(acc.last_ip, ip);
ck_assert(acc.last_login_time > 0);

/**
 * Test recording a failed login
 */
#test test_account_record_login_failure
account_t acc = create_dummy_account();
account_record_login_failure(& acc);
ck_assert_int_eq(acc.login_fail_count, 1);
ck_assert_int_eq(acc.login_count, 0);

/* 
 * Account Summary Test Case
 * ----------------------
 * Tests for account summary printing
 */
#tcase account_summary_test_case

/**
 * Test printing an account summary to a file
 */
#test test_account_print_summary
account_t acc = create_dummy_account();
strncpy(acc.userid, "dave", sizeof(acc.userid) - 1);
acc.userid[sizeof(acc.userid) - 1] = '\0';

strncpy(acc.email, "dave@example.com", sizeof(acc.email) - 1);
acc.email[sizeof(acc.email) - 1] = '\0';

memcpy(acc.birthdate, "1985-12-02", BIRTHDATE_LENGTH);

acc.login_count = 5;
acc.login_fail_count = 1;
acc.last_login_time = 1700000000;
acc.last_ip = inet_addr("127.0.0.1");
acc.unban_time = 0;
acc.expiration_time = 0;
ck_assert(account_print_summary(& acc, STDOUT_FILENO));

/* 
 * Password Handling Test Cases
 * -------------------------
 * Tests for password validation and updates
 */
#tcase account_password_test_case

/**
 * Test that updated password hash is not the plaintext password
 */
#test test_account_update_password_neq_plaintext
account_t acc = create_dummy_account();
account_update_password(& acc, "mypassword");
ck_assert(strcmp(acc.password_hash, "mypassword") != 0);

/**
 * Test validation of a correct password
 */
#test test_account_validate_password_ok
account_t acc = create_dummy_account();
ck_assert(account_update_password(& acc, "secretpass"));
ck_assert(account_validate_password(& acc, "secretpass"));

/**
 * Test validation of an incorrect password
 */
#test test_account_validate_password_wrong
account_t acc = create_dummy_account();
ck_assert(account_update_password(& acc, "rightpass"));
ck_assert(!account_validate_password(& acc, "wrongpass"));

// vim: syntax=c :
