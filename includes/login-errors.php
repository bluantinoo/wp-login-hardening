<?php
/**
 * Block 2: the login form no longer tells a wrong name from a wrong password.
 *
 * WordPress says "unknown username" for a name that does not exist and "wrong
 * password" for one that does: a free and unlimited oracle for telling the two
 * apart. The reply for an unknown name or email is rewritten into the one core
 * gives for a wrong password. Reusing the core strings keeps the message
 * translated in every locale.
 *
 * @package WP_Login_Hardening
 */

namespace WP_Login_Hardening\Login_Errors;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Hooks the block.
 */
function register() {
	// After core's username, email and cookie checks, which all run at 20.
	add_filter( 'authenticate', __NAMESPACE__ . '\\generic_login_error', 40, 2 );
}

/**
 * The core wrong-password error for a username or email, lost password link
 * included: without that trailing link the two replies would still differ.
 *
 * @param string $username Submitted username or email.
 * @return \WP_Error
 */
function wrong_password_error( $username ) {
	if ( is_email( $username ) ) {
		/* translators: %s: Email address. */
		$message = __( '<strong>Error:</strong> The password you entered for the email address %s is incorrect.' ); // phpcs:ignore WordPress.WP.I18n.MissingArgDomain -- core string.
	} else {
		/* translators: %s: User name. */
		$message = __( '<strong>Error:</strong> The password you entered for the username %s is incorrect.' ); // phpcs:ignore WordPress.WP.I18n.MissingArgDomain -- core string.
	}

	// The link is built as core builds it, unescaped: esc_url() would turn &
	// into &#038; when a plugin adds query arguments, and the two replies
	// would differ again.
	return new \WP_Error(
		'incorrect_password',
		sprintf( $message, '<strong>' . esc_html( $username ) . '</strong>' ) .
		' <a href="' . wp_lostpassword_url() . '">' . // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		__( 'Lost your password?' ) . // phpcs:ignore WordPress.WP.I18n.MissingArgDomain -- core string.
		'</a>'
	);
}

/**
 * Rewrites "unknown username" and "unknown email" into "wrong password".
 *
 * @param null|\WP_User|\WP_Error $user     Result so far.
 * @param string                  $username Submitted username or email.
 * @return null|\WP_User|\WP_Error
 */
function generic_login_error( $user, $username ) {
	if ( ! is_wp_error( $user ) ) {
		return $user;
	}

	$codes = $user->get_error_codes();
	if ( ! in_array( 'invalid_username', $codes, true ) && ! in_array( 'invalid_email', $codes, true ) ) {
		return $user;
	}

	// A captcha has to answer for unknown names too. WP reCaptcha Integration
	// checks on wp_authenticate_user, which core only reaches for a name that
	// exists: a real name without a valid captcha got "the Captcha didn't
	// verify", a made-up one got the password message, and the oracle was
	// back. Calling the plugin's own check keeps its message and translation.
	// Not apply_filters( 'wp_authenticate_user' ) with a placeholder user:
	// logging plugins listen there too and would record a bogus failed login.
	if ( class_exists( '\WP_reCaptcha' ) && method_exists( '\WP_reCaptcha', 'instance' ) ) {
		$captcha = \WP_reCaptcha::instance()->deny_login( new \WP_User() );
		if ( is_wp_error( $captcha ) ) {
			return $captcha;
		}
	}

	// Core checks the password only for names that exist, so an unknown name
	// came back measurably faster. Hashing a throwaway password costs about
	// what checking one does, as long as stored hashes use the current
	// algorithm: old phpass hashes check faster until the user logs in again.
	wp_hash_password( wp_generate_password( 20, false ) );

	return wrong_password_error( (string) $username );
}
