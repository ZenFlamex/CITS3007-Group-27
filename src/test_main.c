#ifdef ALTERNATE_MAIN

#include "login.h"
#include "account.h"
#include <stdio.h>
#include <unistd.h>
#include <time.h>

void test_login(const char *userid, const char *password) {
    login_session_data_t session;
    login_result_t result = handle_login(
        userid,
        password,
        0x7F000001,     // 127.0.0.1
        time(NULL),     // current time
        STDOUT_FILENO,  // client output (to terminal)
        STDERR_FILENO,  // log output (to terminal)
        &session
    );

    printf("[TEST] Attempt login for userid='%s' password='%s' => result: %d\n\n",
           userid, password, result);
}

int main() {
    printf("========== Starting Login Tests ==========\n\n");

    // 测试1: 用户不存在
    test_login("nonexistent_user", "any_password");

    // 测试2: 密码错误 (前提是 bob 的密码不是 "wrongpass")
    test_login("bob", "wrongpass");

    // 测试3: 被封禁账号
    // 你可以手动在 account_lookup_by_userid() 中设置 bob 的 unban_time > 当前时间来模拟
    test_login("bob_banned", "correctpassword");

    // 测试4: 已过期账号
    // 同样需要 account_lookup_by_userid() 返回 expiration_time < 当前时间
    test_login("bob_expired", "correctpassword");

    // 测试5: 登录成功
    test_login("bob", "correctpassword");  // 这里的密码应与实际加密一致

    printf("========== End of Tests ==========\n");
    return 0;
}

#endif
