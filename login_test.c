// DO NOT SUBMIT THIS FILE
//
// This file is intended for testing handle_login() assuming all dependencies are correctly implemented.
//
// To compile:
//   gcc -std=c11 -Wall -Wextra -pedantic-errors -Wconversion -fsanitize=address,undefined \
//       -I./src src/login.c src/stubs.c src/account.c login_test.c -o login_test
//
// To run:
//   ./login_test

#include "login.h"
#include <stdio.h>

void test_login(const char *userid, const char *password) {
    // Run the login function with dummy IP/location/session fields
    login_result_t result = handle_login(userid, password, 0, 0, 0, 0);
    // Print the login result (just the numeric code)
    printf("[LOGIN TEST] userid='%s', password='%s' => result: %d\n",
           userid, password, result);
}

int main(void) {
    printf("========== Starting Login Tests ==========\n");
    // Test case 1: Non-existent user
    test_login("nonexistent_user", "any_password");
    // Test case 2: Valid user, incorrect password
    test_login("bob", "wrongpass");
    // Test case 3: User account is banned
    test_login("bob_banned", "correctpassword");
    // Test case 4: User account is expired
    test_login("bob_expired", "correctpassword");
    // Test case 5: Valid login
    test_login("bob", "correctpassword");

    printf("=========== End of Login Tests ===========\n");
    return 0;
}
