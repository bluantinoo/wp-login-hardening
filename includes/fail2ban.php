<?php
/**
 * Block 6: one log line per failed or blocked attempt, for fail2ban.
 *
 * The lines for failed logins are the ones the WP fail2ban plugin writes, with
 * the same syslog tag and facility, so its filters keep working and a site can
 * move from one plugin to the other without rewriting its jails.
 *
 * @package WP_Login_Hardening
 */

namespace WP_Login_Hardening\Fail2ban;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Hooks the events.
 */
function register() {
	add_action( 'wp_login_failed', __NAMESPACE__ . '\\on_login_failed', 10, 2 );
	add_filter( 'authenticate', __NAMESPACE__ . '\\on_empty_username', PHP_INT_MAX, 2 );
	add_filter( 'woocommerce_process_login_errors', __NAMESPACE__ . '\\on_woocommerce_login_errors', PHP_INT_MAX, 2 );
	// Priority 1: captcha plugins hook here too, and some of them wp_die().
	add_action( 'lostpassword_post', __NAMESPACE__ . '\\on_lostpassword', 1 );
	add_action( 'application_password_failed_authentication', __NAMESPACE__ . '\\on_application_password_failed' );
	add_action( 'wp_login_hardening_blocked', __NAMESPACE__ . '\\on_blocked' );
}

/**
 * A login that reached wp_authenticate() and failed: wp-login.php, the
 * WooCommerce form on any URL, XML-RPC.
 *
 * The block that makes login errors identical rewrites unknown names into
 * wrong passwords, so whether the user exists is read from the database, the
 * way core looks it up: by login first, then by email.
 *
 * @param string         $username Submitted username or email.
 * @param \WP_Error|null $error    Why it failed.
 */
function on_login_failed( $username, $error = null ) {
	$username = (string) $username;

	// An empty name here is not an attempt: core fires wp_login_failed with no
	// name when a plain visit to wp-login.php finds an expired session cookie.
	// Submitted forms with no name are logged by on_empty_username().
	if ( '' === trim( $username ) ) {
		return;
	}

	$user = get_user_by( 'login', $username );
	if ( ! $user && is_email( $username ) ) {
		$user = get_user_by( 'email', $username );
	}

	if ( $user ) {
		log_event( 'Authentication failure for ' . clean( $username ) );
	} else {
		log_event( 'Authentication attempt for unknown user ' . clean( $username ) );
	}
}

/**
 * A login submitted with no name (wp-login.php, XML-RPC). Core does not fire
 * wp_login_failed for it, and every plain visit to wp-login.php produces the
 * same error, so only POST requests count.
 *
 * @param null|\WP_User|\WP_Error $user     Result so far.
 * @param string                  $username Submitted username.
 * @return null|\WP_User|\WP_Error
 */
function on_empty_username( $user, $username ) {
	if ( is_wp_error( $user ) && in_array( 'empty_username', $user->get_error_codes(), true )
		&& '' === trim( (string) $username )
		&& isset( $_SERVER['REQUEST_METHOD'] ) && 'POST' === $_SERVER['REQUEST_METHOD'] ) {
		log_event( 'Empty username' );
	}
	return $user;
}

/**
 * A WooCommerce login refused before wp_signon(), usually by a captcha:
 * wp_login_failed never fires for it.
 *
 * @param \WP_Error $error    Validation errors.
 * @param string    $username Submitted username or email.
 * @return \WP_Error
 */
function on_woocommerce_login_errors( $error, $username ) {
	if ( is_wp_error( $error ) && $error->has_errors() ) {
		log_event( 'WooCommerce login rejected before authentication for ' . clean( (string) $username ) );
	}
	return $error;
}

/**
 * A lost password form submitted by a visitor, valid user or not: it is how
 * mail bombing and reset flooding show up.
 *
 * Only the public forms post user_login. Resets sent by an administrator from
 * the user list or a profile run the same core function and must not count,
 * or a bulk reset would get the administrator banned.
 */
function on_lostpassword() {
	// phpcs:ignore WordPress.Security.NonceVerification.Missing -- read-only, for the log line; core and WooCommerce verify the form.
	if ( ! isset( $_POST['user_login'] ) || current_user_can( 'edit_users' ) ) {
		return;
	}
	// phpcs:ignore WordPress.Security.NonceVerification.Missing
	log_event( 'Password reset form submitted for ' . clean( (string) wp_unslash( $_POST['user_login'] ) ) );
}

/**
 * A wrong application password on a REST request.
 *
 * Over XML-RPC the same check runs inside wp_authenticate(), which then fires
 * wp_login_failed: that line is enough.
 */
function on_application_password_failed() {
	if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
		return;
	}
	$username = isset( $_SERVER['PHP_AUTH_USER'] ) ? (string) wp_unslash( $_SERVER['PHP_AUTH_USER'] ) : '';
	log_event( 'Application password failure for ' . clean( $username ) );
}

/**
 * A request refused by another block of this plugin.
 *
 * @param string $what enumeration or xmlrpc.
 */
function on_blocked( $what ) {
	if ( 'enumeration' === $what ) {
		log_event( 'Blocked user enumeration attempt' );
	} elseif ( 'xmlrpc' === $what ) {
		log_event( 'XML-RPC request blocked' );
	}
}

/**
 * Makes a value chosen by the client safe to put in a log line.
 *
 * A name with a line break would write a second, forged line, with any
 * address at its end: a way to get someone else banned.
 *
 * @param string $value Raw value.
 * @return string
 */
function clean( $value ) {
	$value = preg_replace( '/[\x00-\x1F\x7F]+/u', ' ', $value );
	$value = null === $value ? '' : trim( $value );
	if ( function_exists( 'mb_substr' ) ) {
		return mb_substr( $value, 0, 60 );
	}
	return substr( $value, 0, 60 );
}

/**
 * Writes one event, with the client address at the end. Nothing is written
 * when the client address cannot be known: a line with a proxy's address
 * would get the proxy banned.
 *
 * @param string $message Event text.
 * @return bool Whether the line was written.
 */
function log_event( $message ) {
	$ip = client_ip();
	if ( '' === $ip ) {
		return false;
	}
	return write_line( $message . ' from ' . $ip );
}

/**
 * Writes the test line from the settings page.
 *
 * @return array{ok: bool, message: string}
 */
function write_test() {
	$path = log_file();

	if ( null !== $path && null !== log_file_problem( $path ) ) {
		return [
			'ok'      => false,
			/* translators: %s: reason. */
			'message' => sprintf( __( 'Test line not written: %s', 'wp-login-hardening' ), log_file_error( $path ) ),
		];
	}

	$ip = client_ip();
	if ( '' === $ip ) {
		return [
			'ok'      => false,
			'message' => __( 'Test line not written: the client address cannot be determined. The request comes from a trusted proxy, and the last entry of X-Forwarded-For is missing, invalid or itself a trusted proxy. As things stand, nothing would be logged.', 'wp-login-hardening' ),
		];
	}

	$ok = write_line( 'Login Hardening test line from ' . $ip );

	if ( null === $path ) {
		return [
			'ok'      => $ok,
			'message' => $ok
				? __( 'Test line handed to syslog. Look for it in the log that receives the auth facility, usually /var/log/auth.log. If it is not there, PHP cannot reach syslog (for example a chrooted PHP-FPM pool): use a log file instead.', 'wp-login-hardening' )
				: __( 'Syslog refused the test line.', 'wp-login-hardening' ),
		];
	}

	return [
		'ok'      => $ok,
		'message' => $ok
			/* translators: %s: file path. */
			? sprintf( __( 'Test line written to %s.', 'wp-login-hardening' ), $path )
			/* translators: %s: file path. */
			: sprintf( __( 'Could not write to %s.', 'wp-login-hardening' ), $path ),
	];
}

/**
 * Syslog tag, as WP fail2ban writes it: wordpress(<host of the site>).
 * The host comes from the site URL, never from the request, whose Host
 * header the client chooses.
 *
 * @return string
 */
function tag() {
	$host = wp_parse_url( home_url(), PHP_URL_HOST );
	return 'wordpress(' . ( $host ? $host : 'localhost' ) . ')';
}

/**
 * Path of the log file, if one is configured. Only a constant can set it.
 *
 * @return string|null
 */
function log_file() {
	if ( ! defined( 'WP_LOGIN_HARDENING_FAIL2BAN_LOG' ) || '' === (string) WP_LOGIN_HARDENING_FAIL2BAN_LOG ) {
		return null;
	}
	return (string) WP_LOGIN_HARDENING_FAIL2BAN_LOG;
}

/**
 * Why a log file cannot be used, as a code, or null if it can.
 *
 * The file holds text chosen by whoever attacks the login. Inside the web
 * root, or with an extension the server executes, it would be served or run.
 *
 * @param string $path File path.
 * @return string|null relative, extension, folder, web_root, not_writable.
 */
function log_file_problem( $path ) {
	if ( '/' !== substr( $path, 0, 1 ) ) {
		return 'relative';
	}
	if ( '.log' !== strtolower( substr( $path, -4 ) ) ) {
		return 'extension';
	}

	$dir = realpath( dirname( $path ) );
	if ( false === $dir || ! is_dir( $dir ) ) {
		return 'folder';
	}

	// The web root can sit above ABSPATH when WordPress is in a subfolder.
	$roots = [ ABSPATH ];
	if ( ! empty( $_SERVER['DOCUMENT_ROOT'] ) ) {
		$roots[] = (string) $_SERVER['DOCUMENT_ROOT'];
	}
	foreach ( $roots as $root ) {
		$root = realpath( $root );
		if ( false !== $root && 0 === strpos( $dir . '/', rtrim( $root, '/' ) . '/' ) ) {
			return 'web_root';
		}
	}

	if ( file_exists( $path ) ? ! is_writable( $path ) : ! is_writable( $dir ) ) {
		return 'not_writable';
	}

	return null;
}

/**
 * Why a log file cannot be used, in words, or null if it can.
 *
 * @param string $path File path.
 * @return string|null
 */
function log_file_error( $path ) {
	switch ( log_file_problem( $path ) ) {
		case 'relative':
			return __( 'The log file path must be absolute.', 'wp-login-hardening' );
		case 'extension':
			return __( 'The log file name must end in .log.', 'wp-login-hardening' );
		case 'folder':
			return __( 'The folder of the log file does not exist.', 'wp-login-hardening' );
		case 'web_root':
			return __( 'The log file must be outside the folders the web server serves.', 'wp-login-hardening' );
		case 'not_writable':
			return __( 'PHP cannot write the log file.', 'wp-login-hardening' );
	}
	return null;
}

/**
 * Sends a line to syslog, or appends it to the log file.
 *
 * @param string $line Line without date and tag.
 * @return bool
 */
function write_line( $line ) {
	$path = log_file();

	if ( null === $path ) {
		if ( ! function_exists( 'openlog' ) ) {
			return false;
		}
		openlog( tag(), LOG_NDELAY | LOG_PID, LOG_AUTH );
		$ok = syslog( LOG_NOTICE, $line );
		closelog();
		return $ok;
	}

	if ( null !== log_file_problem( $path ) ) {
		return false;
	}

	// WordPress runs PHP in UTC: the offset is written so that fail2ban does
	// not read the time in the server's zone.
	$host = function_exists( 'gethostname' ) ? gethostname() : 'localhost';
	$text = gmdate( 'Y-m-d\TH:i:s' ) . '+00:00 ' . $host . ' ' . tag() . '[' . getmypid() . ']: ' . $line . "\n";
	$new  = ! file_exists( $path );

	// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
	$ok = false !== file_put_contents( $path, $text, FILE_APPEND | LOCK_EX );

	// Usernames and addresses: readable by the owner and its group only.
	if ( $ok && $new ) {
		chmod( $path, 0640 ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod
	}

	return $ok;
}

/**
 * The client address, or an empty string if it cannot be known.
 *
 * REMOTE_ADDR, unless the request comes from a trusted proxy. Then the last
 * address in X-Forwarded-For is the one the proxy appended for the
 * connection it received, and it is the only entry that can be trusted: the
 * rest was written by whoever sent the request. If that address is itself a
 * trusted proxy, the client is unknown and nothing is logged: a Cloudflare
 * Worker, for example, can reach the origin from Cloudflare's own ranges
 * with a header its author chose.
 *
 * @return string
 */
function client_ip() {
	$remote = isset( $_SERVER['REMOTE_ADDR'] ) ? (string) $_SERVER['REMOTE_ADDR'] : '';
	if ( ! filter_var( $remote, FILTER_VALIDATE_IP ) ) {
		return '';
	}

	$proxies = \WP_Login_Hardening\trusted_proxies();
	if ( ! $proxies || ! in_ranges( $remote, $proxies ) ) {
		return $remote;
	}

	$hops = empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ? [] : explode( ',', (string) $_SERVER['HTTP_X_FORWARDED_FOR'] );
	$last = trim( (string) end( $hops ) );

	if ( ! filter_var( $last, FILTER_VALIDATE_IP ) || in_ranges( $last, $proxies ) ) {
		return '';
	}

	return $last;
}

/**
 * Whether an entry is an IP address or a CIDR range.
 *
 * @param string $entry Entry.
 * @return bool
 */
function is_valid_range( $entry ) {
	$parts = explode( '/', $entry, 2 );
	$ip    = $parts[0];
	if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
		return false;
	}
	if ( ! isset( $parts[1] ) ) {
		return true;
	}
	$max = false !== strpos( $ip, ':' ) ? 128 : 32;
	return ctype_digit( $parts[1] ) && (int) $parts[1] <= $max;
}

/**
 * Whether an address falls in one of the ranges.
 *
 * @param string   $ip     Address.
 * @param string[] $ranges IP addresses and CIDR ranges.
 * @return bool
 */
function in_ranges( $ip, array $ranges ) {
	$packed = inet_pton( $ip );
	if ( false === $packed ) {
		return false;
	}

	foreach ( $ranges as $range ) {
		$parts = explode( '/', $range, 2 );
		$net   = inet_pton( $parts[0] );
		if ( false === $net || strlen( $net ) !== strlen( $packed ) ) {
			continue;
		}

		$bits = isset( $parts[1] ) ? (int) $parts[1] : strlen( $net ) * 8;
		$full = intdiv( $bits, 8 );
		$rest = $bits % 8;

		if ( substr( $packed, 0, $full ) !== substr( $net, 0, $full ) ) {
			continue;
		}
		if ( 0 === $rest ) {
			return true;
		}

		$mask = ( 0xFF << ( 8 - $rest ) ) & 0xFF;
		if ( ( ord( $packed[ $full ] ) & $mask ) === ( ord( $net[ $full ] ) & $mask ) ) {
			return true;
		}
	}

	return false;
}
