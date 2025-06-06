#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <unistd.h>
#include "login.h"
#include "logging.h"
#include "db.h"
#include "banned.h"

/**
 * Implements business logic for user login.
 *
 *
 * @param userid The user ID to authenticate.
 * @param password The password to validate.
 * @param client_ip The IP address of the client.
 * @param login_time The time of the login attempt.
 * @param client_output_fd File descriptor for client communication.
 * @param session Pointer to session data structure to populate on success.
 * @return A login_result_t indicating the result of the login attempt.
 */
login_result_t handle_login(const char *userid, const char *password,
                            ip4_addr_t client_ip, time_t login_time,
                            int client_output_fd,
                            login_session_data_t *session)
{
  account_t acc;
  if (!account_lookup_by_userid(userid, &acc))
  {
    dprintf(client_output_fd, "Login failed: user not found.\n");
    log_message(LOG_WARN, "Login failed: unknown user '%s'", userid);
    return LOGIN_FAIL_USER_NOT_FOUND;
  }

  if (account_is_banned(&acc))
  {
    dprintf(client_output_fd, "Login failed: account banned.\n");
    log_message(LOG_WARN, "Login failed: user '%s' is banned", userid);
    account_record_login_failure(&acc);
    return LOGIN_FAIL_ACCOUNT_BANNED;
  }

  if (account_is_expired(&acc))
  {
    dprintf(client_output_fd, "Login failed: account expired.\n");
    log_message(LOG_WARN, "Login failed: user '%s' is expired", userid);
    account_record_login_failure(&acc);
    return LOGIN_FAIL_ACCOUNT_EXPIRED;
  }

  // Check for too many consecutive login failures
  if (acc.login_fail_count > 10)
  {
    dprintf(client_output_fd, "Login failed: too many failed attempts. Account is locked.\n");
    log_message(LOG_WARN, "Login failed: user '%s' has too many failed attempts (%u)",
                userid, acc.login_fail_count);

    return LOGIN_FAIL_BAD_PASSWORD;
  }

  if (!account_validate_password(&acc, password))
  {
    dprintf(client_output_fd, "Login failed: incorrect password.\n");
    account_record_login_failure(&acc);
    log_message(LOG_WARN, "Login failed: incorrect password for user '%s'", userid);
    return LOGIN_FAIL_BAD_PASSWORD;
  }

  account_record_login_success(&acc, client_ip);

  session->account_id = (int)acc.account_id;
  session->session_start = login_time;
  session->expiration_time = login_time + 3600; // 1 hour session

  dprintf(client_output_fd, "Login successful. Welcome, %s!\n", userid);
  log_message(LOG_INFO, "Login success for user '%s'", userid);

  return LOGIN_SUCCESS;
}