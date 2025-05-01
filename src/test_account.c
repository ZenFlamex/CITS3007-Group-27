// DO NOT SUBMIT THIS FILE
// To compile: gcc -std=c11 -pedantic-errors -Wall -Wextra -Wconversion -fsanitize=address,undefined,leak -g test_account.c account.c -o test_account
// Run with valgrind: gcc -std=c11 -pedantic-errors -Wall -Wextra -Wconversion -fsanitize=undefined -g test_account.c account.c -o test_account && valgrind --leak-check=full ./test_account

#include "account.h"
#include "login.h" 
#include <stdio.h>
#include <assert.h>
#include <time.h>

/**
 * Create a dummy account for testing purposes.
 */
static account_t create_dummy_account(void)
{
    account_t acc = {0};
    acc.unban_time = 0;
    acc.expiration_time = 0;
    return acc;
}

// --- LOGIN TESTS SECTION ---
void test_login(const char *userid, const char *password) {
    login_result_t result = handle_login(userid, password, 0, 0, 0, 0);
    printf("[LOGIN TEST] userid='%s', password='%s' => result: %d\n",
           userid, password, result);
}
//To compile and run the login tests:

//1. Open your terminal and navigate to the project root:

//```bash
//cd CITS3007-Group-27
//2.make CFLAGS='-DALTERNATE_MAIN'
//3./bin/app

static void run_login_tests(void) {
    printf("\n========== Starting Login Tests ==========\n");

    // Test 1: Nonexistent user
    test_login("nonexistent_user", "any_password");

    // Test 2: Incorrect password
    test_login("bob", "wrongpass");

    // Test 3: Banned user
    test_login("bob_banned", "correctpassword");

    // Test 4: Expired account
    test_login("bob_expired", "correctpassword");

    // Test 5: Valid login
    test_login("bob", "correctpassword");

    printf("========== End of Login Tests ==========\n\n");
}

int main(void)
{
    // Test account_set_unban_time() and account_is_banned()
    account_t acc1 = create_dummy_account();
    time_t now = time(NULL);
    if (now == (time_t)(-1))
    {
        printf("Failed to get current time.\n");
        return 1;
    }

    account_set_unban_time(&acc1, now + 10);
    assert(account_is_banned(&acc1) == 1); // Should be banned because unban_time is in the future

    account_set_unban_time(&acc1, now - 10);
    assert(account_is_banned(&acc1) == 0); // Should not be banned because unban_time is in the past

    // Test account_set_expiration_time() and account_is_expired()
    account_t acc2 = create_dummy_account();

    account_set_expiration_time(&acc2, now - 10);
    assert(account_is_expired(&acc2) == 1); // Should be expired because expiration_time is in the past

    account_set_expiration_time(&acc2, now + 10);
    assert(account_is_expired(&acc2) == 0); // Should not be expired because expiration_time is in the future

    // Additional edge case: expiration_time == now
    account_t acc3 = create_dummy_account();
    account_set_expiration_time(&acc3, now);
    assert(account_is_expired(&acc3) == 1); // Should be expired immediately at expiration_time

    printf("All account tests passed.\n");

    // Run login tests
    run_login_tests();

    return 0;
}

