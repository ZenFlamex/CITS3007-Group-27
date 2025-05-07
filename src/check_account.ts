#define CITS3007_PERMISSIVE

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>


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

/* #test test_account_create_works
ck_assert_msg(0, "account_create not yet implemented");
*/

/* #test test_account_create_invalid_email
ck_assert_msg(0, "account_create not yet implemented");
*/

/* #test test_account_create_invalid_birthdate
ck_assert_msg(0, "account_create not yet implemented");
*/

#tcase account_free_test_case

#test test_account_free_with_null
account_free(NULL);
ck_assert(true);


#tcase account_email_test_case

/* #test test_account_set_email
account_t acc = create_dummy_account();
account_set_email(&acc, "new@example.com");
ck_assert_str_eq(acc.email, "new@example.com");
*/

#tcase account_ban_test_case

#test test_account_ban_times
account_t acc = create_dummy_account();
time_t now = time(NULL);
ck_assert(now != (time_t)(-1));
account_set_unban_time(&acc, now + 10);
ck_assert_int_eq(account_is_banned(&acc), 1);
account_set_unban_time(&acc, now - 10);
ck_assert_int_eq(account_is_banned(&acc), 0);
account_set_unban_time(&acc, 0);
ck_assert_int_eq(account_is_banned(&acc), 0);

#tcase account_expiration_test_case

#test test_account_expiration_times
account_t acc = create_dummy_account();
time_t now = time(NULL);
ck_assert(now != (time_t)(-1));
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
account_t acc = create_dummy_account();
ip4_addr_t ip = inet_addr("127.0.0.1");
account_record_login_success(&acc, ip);
ck_assert_int_eq(acc.login_count, 1);
ck_assert_int_eq(acc.login_fail_count, 0);
ck_assert_int_eq(acc.last_ip, ip);
ck_assert(acc.last_login_time > 0);

#test test_account_record_login_failure
account_t acc = create_dummy_account();
account_record_login_failure(&acc);
ck_assert_int_eq(acc.login_fail_count, 1);
ck_assert_int_eq(acc.login_count, 0);


#tcase account_summary_test_case

#test test_account_print_summary
account_t acc = create_dummy_account();
strncpy(acc.userid, "dave", sizeof(acc.userid) - 1);
acc.userid[sizeof(acc.userid) - 1] = '\0';

strncpy(acc.email, "dave@example.com", sizeof(acc.email) - 1);
acc.email[sizeof(acc.email) - 1] = '\0';

strncpy(acc.birthdate, "1985-12-2", sizeof(acc.birthdate));
acc.birthdate[sizeof(acc.birthdate) - 1] = '\0'; // ensure null-termination

acc.login_count = 5;
acc.login_fail_count = 1;
acc.last_login_time = 1700000000;
acc.last_ip = inet_addr("127.0.0.1");
acc.unban_time = 0;
acc.expiration_time = 0;
ck_assert(account_print_summary(&acc, STDOUT_FILENO));


#tcase account_password_test_case

#test test_account_update_password_neq_plaintext
account_t acc = create_dummy_account();
account_update_password(&acc, "mypassword");
ck_assert(strcmp(acc.password_hash, "mypassword") != 0);

#test test_account_validate_password_ok
account_t acc = create_dummy_account();
ck_assert(account_update_password(&acc, "secretpass"));
ck_assert(account_validate_password(&acc, "secretpass"));

#test test_account_validate_password_wrong
account_t acc = create_dummy_account();
ck_assert(account_update_password(&acc, "rightpass"));
ck_assert(!account_validate_password(&acc, "wrongpass"));


// vim: syntax=c :