// DO NOT SUBMIT THIS FILE
// To compile: gcc -std=c11 -pedantic-errors -Wall -Wextra -Wconversion -fsanitize=address,undefined,leak -g test_account.c account.c -o test_account
// Run with valgrind: gcc -std=c11 -pedantic-errors -Wall -Wextra -Wconversion -fsanitize=undefined -g test_account.c account.c -o test_account && valgrind --leak-check=full ./test_account

#include "account.h"
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

int main(void)
{
    // BAN AND EXPIRE ACCOUNT TESTS
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

    printf("All tests passed.\n");
    return 0;
}
