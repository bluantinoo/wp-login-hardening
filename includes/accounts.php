<?php
/**
 * Blocks 4 and 5: accounts without a role, and application passwords.
 *
 * @package WP_Login_Hardening
 */

namespace WP_Login_Hardening\Accounts;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Hooks block 4.
 *
 * Retired accounts and author-only accounts keep their content and lose their
 * role: from then on they can never be used.
 */
function register_roleless() {
	add_filter( 'authenticate', __NAMESPACE__ . '\\block_roleless_login', 30, 2 );
	add_filter( 'determine_current_user', __NAMESPACE__ . '\\drop_roleless_session', 99 );
}

/**
 * Hooks block 5.
 */
function register_app_passwords() {
	// Application passwords authenticate REST and XML-RPC calls with the
	// password alone, which is the classic way around two-factor login.
	add_filter( 'wp_is_application_passwords_available', '__return_false' );
}

/**
 * Users without a role cannot log in.
 *
 * Runs after core has checked the password, so only someone who knows the
 * right one gets here, and answers with the core wrong-password message: a
 * retired account looks exactly like a mistyped password.
 *
 * @param null|\WP_User|\WP_Error $user     Result so far.
 * @param string                  $username Submitted username or email.
 * @return null|\WP_User|\WP_Error
 */
function block_roleless_login( $user, $username ) {
	if ( ! $user instanceof \WP_User || has_role( $user->ID ) ) {
		return $user;
	}
	return \WP_Login_Hardening\Login_Errors\wrong_password_error( (string) $username );
}

/**
 * ...and a session is never theirs, whatever way it was opened.
 *
 * The filter above only covers the password form. Auth cookies issued before
 * the role was removed stay valid, and plugins can set the cookie without
 * going through authenticate. Resolving the current user from the cookie is
 * the step every later request shares, so a user without a role is turned
 * back into a visitor here, from the next request on.
 *
 * @param int|false $user_id Resolved user ID.
 * @return int|false
 */
function drop_roleless_session( $user_id ) {
	if ( ! $user_id || has_role( (int) $user_id ) ) {
		return $user_id;
	}
	return 0;
}

/**
 * Whether the user holds any role or capability, read straight from the table.
 *
 * Deliberately not get_userdata(): loading a WP_User fires filters that other
 * plugins answer by asking for the current user, which re-enters
 * determine_current_user and recursed until PHP ran out of memory.
 *
 * @param int $user_id User ID.
 * @return bool
 */
function has_role( $user_id ) {
	global $wpdb;

	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- see above: no user object, no filters.
	$caps = $wpdb->get_var(
		$wpdb->prepare(
			"SELECT meta_value FROM {$wpdb->usermeta} WHERE user_id = %d AND meta_key = %s",
			$user_id,
			$wpdb->get_blog_prefix() . 'capabilities'
		)
	);
	$caps = maybe_unserialize( $caps );

	return is_array( $caps ) && [] !== array_filter( $caps );
}
