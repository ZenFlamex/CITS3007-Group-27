// DO NOT SUBMIT THIS FILE
// Combined test specification for account and login logic using Check framework (.ts)
// To use: checkmk src/check_account.ts > src/check_account.c

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
#include "login.h"

#define ARR_SIZE(arr)(sizeof(arr) / sizeof((arr)[0]))

static account_t create_dummy_account(void)
{
    account_t acc = { 0 };
    acc.unban_time = 0;
    acc.expiration_time = 0;
    return acc;
}

#suite account_suite

#tcase account_create_test_case

#test test_account_create_works
ck_assert_msg(0, "account_create not yet implemented");

#test test_account_create_invalid_email
ck_assert_msg(0, "account_create not yet implemented");

#test test_account_create_invalid_birthdate
ck_assert_msg(0, "account_create not yet implemented");

#tcase account_free_test_case

#test test_account_free_with_null
ck_assert_msg(0, "account_free not yet implemented");

#tcase account_email_test_case

#test test_account_set_email
ck_assert_msg(0, "account_set_email not yet implemented");

#tcase account_ban_test_case

#test test_account_ban_times
account_t acc = create_dummy_account();
time_t now = time(NULL);
if (now == (time_t)(-1)) {
    ck_assert_msg(0, "Failed to get current time");
}
account_set_unban_time(&acc, now + 10);
ck_assert_int_eq(account_is_banned(&acc), 1);
account_set_unban_time(&acc, now - 10);
ck_assert_int_eq(account_is_banned(&acc), 0);
account_set_unban_time(&acc, 0);
ck_assert_int_eq(account_is_banned(&acc), 0);

#tcase account_expiration_test_case

#test test_account_expiration_times
account_t acc = create_dummy_account();
now = time(NULL);
if (now == (time_t)(-1)) {
    ck_assert_msg(0, "Failed to get current time");
}
account_set_expiration_time(&acc, now - 10);
ck_assert_int_eq(account_is_expired(&acc), 1);
account_set_expiration_time(&acc, now + 10);
ck_assert_int_eq(account_is_expired(&acc), 0);
account_set_expiration_time(&acc, now);
ck_assert_int_eq(account_is_expired(&acc), 1);
account_set_expiration_time(&acc, 0);
ck_assert_int_eq(account_is_expired(&acc), 0);

#tcase account_login_record_test_case

#test test_account_record_login_success
ck_assert_msg(0, "account_record_login_success not yet implemented");

#test test_account_record_login_failure
ck_assert_msg(0, "account_record_login_failure not yet implemented");

#tcase account_summary_test_case

#test test_account_print_summary
ck_assert_msg(0, "account_print_summary not yet implemented");

#tcase account_password_test_case

#test test_account_update_password_neq_plaintext
ck_assert_msg(0, "account_update_password not yet implemented");

#test test_account_validate_password_ok
ck_assert_msg(0, "account_validate_password not yet implemented");

#test test_account_validate_password_wrong
ck_assert_msg(0, "account_validate_password not yet implemented");

#tcase login_test_case

#test test_login_nonexistent_user
login_result_t result = handle_login("nonexistent_user", "any_password", 0, 0, 0, 0);
ck_assert_int_eq(result, LOGIN_ERR_NO_USER);

#test test_login_wrong_password
result = handle_login("bob", "wrongpass", 0, 0, 0, 0);
ck_assert_int_eq(result, LOGIN_ERR_BAD_PASSWORD);

#test test_login_success
result = handle_login("bob", "correctpassword", 0, 0, 0, 0);
ck_assert_int_eq(result, LOGIN_SUCCESS);
