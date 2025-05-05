#define CITS3007_PERMISSIVE

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include <time.h>
#include <unistd.h>

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
 * TODO: This test will fail until account_free is properly implemented
 */
#test test_account_free_with_null
// TODO: Implement account_free function to pass this test
// Should not crash when passed NULL
ck_assert_msg(0, "account_free not yet implemented");

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
 * TODO: This test will fail until account_record_login_success is implemented
 */
#test test_account_record_login_success
// TODO: Implement account_record_login_success function to pass this test
ck_assert_msg(0, "account_record_login_success not yet implemented");

/**
 * Test recording a failed login
 * TODO: This test will fail until account_record_login_failure is implemented
 */
#test test_account_record_login_failure
// TODO: Implement account_record_login_failure function to pass this test
ck_assert_msg(0, "account_record_login_failure not yet implemented");

/* 
 * Account Summary Test Case
 * ----------------------
 * Tests for account summary printing
 */
#tcase account_summary_test_case

/**
 * Test printing an account summary to a file
 * TODO: This test will fail until account_print_summary is implemented
 */
#test test_account_print_summary
// TODO: Implement account_print_summary function to pass this test
ck_assert_msg(0, "account_print_summary not yet implemented");

/* 
 * Password Handling Test Cases
 * -------------------------
 * Tests for password validation and updates
 */
#tcase account_password_test_case

/**
 * Test that updated password hash is not the plaintext password
 * TODO: This test will fail until account_update_password is implemented
 */
#test test_account_update_password_neq_plaintext
// TODO: Implement account_update_password function to pass this test
ck_assert_msg(0, "account_update_password not yet implemented");

/**
 * Test validation of a correct password
 * TODO: This test will fail until account_validate_password is implemented
 */
#test test_account_validate_password_ok
// TODO: Implement account_validate_password function to pass this test
ck_assert_msg(0, "account_validate_password not yet implemented");

/**
 * Test validation of an incorrect password
 * TODO: This test will fail until account_validate_password is implemented
 */
#test test_account_validate_password_wrong
// TODO: Implement account_validate_password function to pass this test
ck_assert_msg(0, "account_validate_password not yet implemented");

// vim: syntax=c :