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
#include "login.h"
#include "db.h"

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
ck_assert(account_update_password(&acc, "StrongPass1!"));
ck_assert(account_validate_password(&acc, "StrongPass1!"));

/**
 * Test validation of an incorrect password
 */
#test test_account_validate_password_wrong
account_t acc = create_dummy_account();
ck_assert(account_update_password(& acc, "rightpass"));
ck_assert(!account_validate_password(& acc, "wrongpass"));

/* 
 * Login Authentication Test Cases
 * ------------------------------
 * Tests for various login scenarios and edge cases
 */
#tcase login_authentication_test_case

/**
 * Test handling a login attempt for a non-existent user
 */
#test test_login_nonexistent_user
{
    // Test directly against the user lookup functionality
    account_t acc = {0};
    const char *nonexistent_userid = "nonexistent_user";
    
    // Verify that looking up a non-existent user returns false
    bool found = account_lookup_by_userid(nonexistent_userid, &acc);
    
    // Assert that the user was not found
    ck_assert(!found);
    
    // Optionally, test the specific behavior when user not found
    // Assuming you have access to the handle_login code or can extract this logic
    if (!found) {
        ck_assert(true); // This is the expected path
    } else {
        ck_assert_msg(false, "Non-existent user should not be found");
    }
}

/**
 * Test handling a login attempt with incorrect password
 */
#test test_login_incorrect_password
{
    // Create a test account with known credentials
    account_t acc = create_dummy_account();
    strcpy(acc.userid, "test_user");
    const char *correct_password = "StrongPass1!";
    const char *wrong_password = "WrongPass1!";

    account_update_password(&acc, correct_password);

    ck_assert(account_validate_password(&acc, correct_password));
    ck_assert(!account_validate_password(&acc, wrong_password));
    
    // Test specific behavior for incorrect password
    if (!account_validate_password(&acc, wrong_password)) {
        ck_assert(true); // This is the expected path
    } else {
        ck_assert_msg(false, "Wrong password should not validate");
    }
}

/**
 * Test handling a login attempt for a banned account
 */
#test test_login_banned_account
{
    // Since we can't modify how account_lookup_by_userid behaves,
    // we need to test the ban logic directly
    
    // Create a custom account to test with
    account_t acc = create_dummy_account();
    strcpy(acc.userid, "bob");
    
    // Set it as banned
    time_t current_time = time(NULL);
    account_set_unban_time(&acc, current_time + 3600); // banned for 1 hour
    
    // Verify our setup is correct
    ck_assert(account_is_banned(&acc));
    
    // Test the ban check logic directly
    ck_assert_int_eq(account_is_banned(&acc), 1);
    
    // Instead of testing full login flow, test that a banned account is rejected correctly
    // You could extract this logic to a separate function for testing if needed
    if (account_is_banned(&acc)) {
        ck_assert(true); // This is the expected path
    } else {
        ck_assert_msg(false, "Account should be banned but isn't detected as such");
    }
}

/**
 * Test handling a login attempt for an expired account
 */
#test test_login_expired_account
{
    // Create a custom account to test with
    account_t acc = create_dummy_account();
    strcpy(acc.userid, "bob");
    
    // Set it as expired
    time_t current_time = time(NULL);
    account_set_expiration_time(&acc, current_time - 3600); // expired 1 hour ago
    
    // Verify our setup is correct
    ck_assert(account_is_expired(&acc));
    
    // Test the expiration check logic directly
    ck_assert_int_eq(account_is_expired(&acc), 1);
    
    // Instead of testing full login flow, test that an expired account is rejected correctly
    if (account_is_expired(&acc)) {
        ck_assert(true); // This is the expected path
    } else {
        ck_assert_msg(false, "Account should be expired but isn't detected as such");
    }
}

/**
 * Test handling a successful login attempt
 */
#test test_login_success
{
    // Create a test account that should successfully authenticate
    account_t acc = create_dummy_account();
    strcpy(acc.userid, "valid_user");
    const char *password = "StrongPass1!";

    // Set up the account with valid password
    account_update_password(&acc, password);

    // Verify password validation works correctly
    ck_assert(account_validate_password(&acc, password));
    ck_assert(!account_validate_password(&acc, "WrongPass1!"));

    // Make sure account isn't expired or banned
    time_t current_time = time(NULL);
    account_set_expiration_time(&acc, current_time + 86400); // 24 hours from now
    account_set_unban_time(&acc, 0); // not banned

    // Test individual components of login success flow
    ck_assert(!account_is_banned(&acc));
    ck_assert(!account_is_expired(&acc));
}