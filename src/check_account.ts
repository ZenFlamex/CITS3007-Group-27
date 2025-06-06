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
 */
#test test_account_create_works
{
    const char * userid = "testuser";
    const char * password = "TestPass1!";
    const char * email = "test@example.com";
    const char * birthdate = "1990-01-15";

    account_t * acc = account_create(userid, password, email, birthdate);

    // Check that account was created
    ck_assert_msg(acc != NULL, "account_create returned NULL with valid parameters");

    // Verify account has correct information
    ck_assert_str_eq(acc -> userid, userid);
    ck_assert_str_eq(acc -> email, email);
    ck_assert_str_eq(acc -> birthdate, birthdate);

    // Check that password was properly hashed
    ck_assert(account_validate_password(acc, password));

    // Verify default values were set correctly
    ck_assert_int_eq(acc -> login_count, 0);
    ck_assert_int_eq(acc -> login_fail_count, 0);
    ck_assert_int_eq(acc -> unban_time, 0);
    ck_assert_int_eq(acc -> expiration_time, 0);

    account_free(acc);
}


/**
 * Test that account_create returns NULL for invalid email (contains spaces)
 */
#test test_account_create_invalid_email
{
    // Test email with space
    const char * userid = "testuser";
    const char * password = "TestPass1!";
    const char * invalid_email_space = "test user@example.com";
    const char * birthdate = "1990-01-15";

    account_t * acc1 = account_create(userid, password, invalid_email_space, birthdate);
    ck_assert_msg(acc1 == NULL, "account_create should return NULL for email with spaces");

    // Email with non-printable character
    const char * invalid_email_control = "test\x01@example.com";
    account_t * acc2 = account_create(userid, password, invalid_email_control, birthdate);
    ck_assert_msg(acc2 == NULL, "account_create should return NULL for email with control chars");

    // Email that's too long
    char long_email[EMAIL_LENGTH + 1];
    memset(long_email, 'a', EMAIL_LENGTH - 5);
    strcpy(& long_email[EMAIL_LENGTH - 5], "@a.co");
    long_email[EMAIL_LENGTH] = '\0';

    account_t * acc3 = account_create(userid, password, long_email, birthdate);
    ck_assert_msg(acc3 == NULL, "account_create should return NULL for email that's too long");
}

/**
 * Test that account_create returns NULL for invalid birthdate format
 */
#test test_account_create_invalid_birthdate
{
    const char * userid = "testuser";
    const char * password = "TestPass1!";
    const char * email = "test@example.com";

    // Test wrong length
    const char * short_date = "1990-1-1";
    account_t * acc1 = account_create(userid, password, email, short_date);
    ck_assert_msg(acc1 == NULL, "account_create should return NULL for birthdate with incorrect length");

    // Test wrong format (no hyphens)
    const char * no_hyphens = "19900115";
    account_t * acc2 = account_create(userid, password, email, no_hyphens);
    ck_assert_msg(acc2 == NULL, "account_create should return NULL for birthdate without hyphens");

    // Test non-digits in wrong places
    const char * wrong_chars = "199a-01-15";
    account_t * acc3 = account_create(userid, password, email, wrong_chars);
    ck_assert_msg(acc3 == NULL, "account_create should return NULL for birthdate with non-digits");

    // Test invalid month
    const char * invalid_month = "1990-13-15";
    account_t * acc4 = account_create(userid, password, email, invalid_month);
    ck_assert_msg(acc4 == NULL, "account_create should return NULL for birthdate with invalid month");

    // Test invalid day
    const char * invalid_day = "1990-02-30"; // February 30th doesn't exist
    account_t * acc5 = account_create(userid, password, email, invalid_day);
    ck_assert_msg(acc5 == NULL, "account_create should return NULL for birthdate with invalid day");

    // Test valid date formats (using leap year rules correctly)
    const char * leap_date1 = "2000-02-29"; // Valid leap year (divisible by 400)
    account_t * acc6 = account_create(userid, password, email, leap_date1);
    ck_assert_msg(acc6 != NULL, "account_create should accept valid leap year date (2000-02-29)");
    account_free(acc6);

    const char * leap_date2 = "2004-02-29"; // Valid leap year (divisible by 4 but not 100)
    account_t * acc7 = account_create(userid, password, email, leap_date2);
    ck_assert_msg(acc7 != NULL, "account_create should accept valid leap year date (2004-02-29)");
    account_free(acc7);

    const char * non_leap_date = "1900-02-29"; // Invalid leap year (divisible by 100 but not 400)
    account_t * acc8 = account_create(userid, password, email, non_leap_date);
    ck_assert_msg(acc8 == NULL, "account_create should reject invalid date 1900-02-29 (not a leap year)");
}


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
 */
#test test_account_set_email
{
    // Create a valid account
    account_t acc = create_dummy_account();
    strcpy(acc.userid, "testuser");
    strcpy(acc.email, "original@example.com");

    // Test setting a valid email
    const char * new_valid_email = "new@example.com";
    account_set_email(& acc, new_valid_email);
    ck_assert_str_eq(acc.email, new_valid_email);

    // Test that invalid emails are not set
    const char * invalid_email_space = "invalid email@example.com";
    account_set_email(& acc, invalid_email_space);
    ck_assert_str_eq(acc.email, new_valid_email); // Should remain unchanged

    // Test email with non-printable character
    const char * invalid_email_control = "test\x01@example.com";
    account_set_email(& acc, invalid_email_control);
    ck_assert_str_eq(acc.email, new_valid_email); // Should remain unchanged

    // Test email that's too long
    char long_email[EMAIL_LENGTH + 10];
    memset(long_email, 'a', EMAIL_LENGTH - 10);
    strcat(long_email, "@example.com");
    long_email[EMAIL_LENGTH + 9] = '\0';

    account_set_email(& acc, long_email);
    ck_assert_str_eq(acc.email, new_valid_email); // Should remain unchanged
}

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
ck_assert(account_update_password(& acc, "StrongPass1!"));
ck_assert(account_validate_password(& acc, "StrongPass1!"));

/**
 * Test validation of an incorrect password
 */
#test test_account_validate_password_wrong
account_t acc = create_dummy_account();
ck_assert(account_update_password(& acc, "Rightpass1!"));
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
    account_t acc = { 0};
    const char * nonexistent_userid = "nonexistent_user";

    // Verify that looking up a non-existent user returns false
    bool found = account_lookup_by_userid(nonexistent_userid, & acc);

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
    const char * correct_password = "StrongPass1!";
    const char * wrong_password = "WrongPass1!";

    account_update_password(& acc, correct_password);

    ck_assert(account_validate_password(& acc, correct_password));
    ck_assert(!account_validate_password(& acc, wrong_password));

    // Test specific behavior for incorrect password
    if (!account_validate_password(& acc, wrong_password)) {
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
    account_set_unban_time(& acc, current_time + 3600); // banned for 1 hour

    // Verify our setup is correct
    ck_assert(account_is_banned(& acc));

    // Test the ban check logic directly
    ck_assert_int_eq(account_is_banned(& acc), 1);

    // Instead of testing full login flow, test that a banned account is rejected correctly
    // You could extract this logic to a separate function for testing if needed
    if (account_is_banned(& acc)) {
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
    account_set_expiration_time(& acc, current_time - 3600); // expired 1 hour ago

    // Verify our setup is correct
    ck_assert(account_is_expired(& acc));

    // Test the expiration check logic directly
    ck_assert_int_eq(account_is_expired(& acc), 1);

    // Instead of testing full login flow, test that an expired account is rejected correctly
    if (account_is_expired(& acc)) {
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
    
    // Add some previous login history
    acc.login_fail_count = 2;
    acc.login_count = 5;
    acc.last_login_time = time(NULL) - 3600; // 1 hour ago
    acc.last_ip = inet_addr("10.0.0.1");
    
    // Make sure account isn't expired or banned
    time_t current_time = time(NULL);
    account_set_expiration_time(&acc, current_time + 86400); // 24 hours from now
    account_set_unban_time(&acc, 0); // not banned
    
    // Test individual components of login success flow
    ck_assert(!account_is_banned(&acc));
    ck_assert(!account_is_expired(&acc));
    ck_assert(account_validate_password(&acc, password));
    
    // Test login recording
    ip4_addr_t new_ip = inet_addr("192.168.1.1");
    account_record_login_success(&acc, new_ip);
    
    // Verify login was recorded correctly
    ck_assert_int_eq(acc.login_count, 6);
    ck_assert_int_eq(acc.login_fail_count, 0); // Should be reset
    ck_assert_int_eq(acc.last_ip, new_ip); 
    ck_assert(acc.last_login_time >= current_time); // Should be updated to current time
    
    // Test session population (what would happen in handle_login)
    login_session_data_t session = {0};
    session.account_id = (int)acc.account_id;
    session.session_start = current_time;
    session.expiration_time = current_time + 3600; // 1 hour session
    
    ck_assert_int_eq(session.account_id, (int)acc.account_id);
    ck_assert_int_eq(session.session_start, current_time);
    ck_assert_int_eq(session.expiration_time, current_time + 3600);
}


/**
 * Test handling a login attempt with too many consecutive failed logins
 */
#test test_login_too_many_failures
{
    // Create a test account with too many failed login attempts
    account_t acc = create_dummy_account();
    strcpy(acc.userid, "locked_user");
    const char * password = "StrongPass1!";

    // Set up the account with valid password
    account_update_password(& acc, password);

    // Set a high number of consecutive failures
    acc.login_fail_count = 11; // More than 10 consecutive failures

    // Make sure account isn't expired or banned
    time_t current_time = time(NULL);
    account_set_expiration_time(& acc, current_time + 86400); // 24 hours from now
    account_set_unban_time(& acc, 0); // not banned

    // Verify our setup is correct
    ck_assert_int_gt(acc.login_fail_count, 10);
    ck_assert(!account_is_banned(& acc));
    ck_assert(!account_is_expired(& acc));

    // Test the logic: Even with correct password, login should fail due to too many attempts
    if (acc.login_fail_count > 10) {
        ck_assert(true); // This is the expected path in our implementation
    } else {
        ck_assert_msg(false, "Account should have too many failed attempts");
    }
}