<?php
/**
 * Block 3: XML-RPC off.
 *
 * The best place to refuse xmlrpc.php is the web server, before PHP starts.
 * That rule usually lives outside version control, though, and a migration or
 * a rewritten .htaccess drops it without anyone noticing: this block keeps the
 * endpoint closed when that happens. WordPress has no setting for it: the
 * enable_xmlrpc option is ignored since 3.5.
 *
 * @package WP_Login_Hardening
 */

namespace WP_Login_Hardening\XMLRPC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Hooks the block.
 */
function register() {
	// xmlrpc_enabled only turns off the methods that need a password. Pingbacks
	// and the public methods would stay, and a pingback can make the site call
	// someone else: emptying the method list closes those too.
	add_filter( 'xmlrpc_enabled', '__return_false' );
	add_filter( 'xmlrpc_methods', '__return_empty_array' );

	// Stop advertising an endpoint that no longer answers: the X-Pingback
	// header and the RSD link are what scanners read first.
	add_filter( 'wp_headers', __NAMESPACE__ . '\\remove_pingback_header' );
	remove_action( 'wp_head', 'rsd_link' );

	add_action( 'init', __NAMESPACE__ . '\\report_request' );
}

/**
 * Removes the X-Pingback header.
 *
 * @param array $headers Response headers.
 * @return array
 */
function remove_pingback_header( $headers ) {
	unset( $headers['X-Pingback'] );
	return $headers;
}

/**
 * Tells the log block about a POST to xmlrpc.php.
 */
function report_request() {
	if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST && isset( $_SERVER['REQUEST_METHOD'] ) && 'POST' === $_SERVER['REQUEST_METHOD'] ) {
		do_action( 'wp_login_hardening_blocked', 'xmlrpc' );
	}
}
