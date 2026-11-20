<?php
/**
 * Plugin Name:       Login Hardening
 * Plugin URI:        https://github.com/bluantinoo/wp-login-hardening
 * Description:       Takes away what a brute force needs: the list of real usernames, a login form that tells a wrong name from a wrong password, XML-RPC, accounts nobody should use. Optionally logs every failed attempt for fail2ban.
 * Version:           2.0.1
 * Author:            Diego Vagnoli
 * Author URI:        https://diegovagnoli.it
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       wp-login-hardening
 * Domain Path:       /languages
 * Requires at least: 6.5
 * Tested up to:      7.1
 * Requires PHP:      7.4
 * Update URI:        https://github.com/bluantinoo/wp-login-hardening
 *
 * @package WP_Login_Hardening
 */

namespace WP_Login_Hardening;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

const VERSION = '2.0.1';

require_once __DIR__ . '/lib/plugin-update-checker/plugin-update-checker.php';

/**
 * Updates come from the GitHub releases of the plugin, not from wordpress.org
 * (the Update URI header keeps WordPress from looking there). Only the zip
 * attached to a release is installed, never the source archive of the tag.
 */
function register_update_checker() {
	$checker = \YahnisElsts\PluginUpdateChecker\v6\PucFactory::buildUpdateChecker(
		'https://github.com/bluantinoo/wp-login-hardening/',
		__FILE__,
		'wp-login-hardening'
	);
	$checker->getVcsApi()->enableReleaseAssets(
		'/^wp-login-hardening\.zip$/',
		\YahnisElsts\PluginUpdateChecker\v6p0\Vcs\Api::REQUIRE_RELEASE_ASSETS
	);

	// Releases only: without this the library falls back to the latest tag and
	// then to the main branch, whose code was never built or released.
	add_filter(
		'puc_vcs_update_detection_strategies-wp-login-hardening',
		static function ( $strategies ) {
			return array_intersect_key( $strategies, [ 'latest_release' => true ] );
		}
	);
}
register_update_checker();

require_once __DIR__ . '/includes/settings.php';
require_once __DIR__ . '/includes/fail2ban.php';
require_once __DIR__ . '/includes/enumeration.php';
require_once __DIR__ . '/includes/login-errors.php';
require_once __DIR__ . '/includes/xmlrpc.php';
require_once __DIR__ . '/includes/accounts.php';

/*
 * Hooks are added when the plugin file loads, not on plugins_loaded: the
 * current user can be resolved as soon as any plugin asks for it, and the
 * account block has to be in place by then.
 */
foreach ( [
	'fail2ban'      => __NAMESPACE__ . '\\Fail2ban\\register',
	'enumeration'   => __NAMESPACE__ . '\\Enumeration\\register',
	'login_errors'  => __NAMESPACE__ . '\\Login_Errors\\register',
	'xmlrpc'        => __NAMESPACE__ . '\\XMLRPC\\register',
	'roleless'      => __NAMESPACE__ . '\\Accounts\\register_roleless',
	'app_passwords' => __NAMESPACE__ . '\\Accounts\\register_app_passwords',
] as $block => $register ) {
	if ( is_enabled( $block ) ) {
		$register();
	}
}

add_action( 'init', __NAMESPACE__ . '\\load_textdomain' );

/**
 * Loads the translations shipped in languages/.
 */
function load_textdomain() {
	load_plugin_textdomain( 'wp-login-hardening', false, dirname( plugin_basename( __FILE__ ) ) . '/languages' );
}

register_activation_hook( __FILE__, __NAMESPACE__ . '\\activate' );

/**
 * Stores the defaults on first activation, so the settings page shows what runs.
 */
function activate() {
	add_option( OPTION, defaults() );
}

add_filter( 'plugin_action_links_' . plugin_basename( __FILE__ ), __NAMESPACE__ . '\\action_links' );

/**
 * Adds a Settings link on the Plugins screen.
 *
 * @param string[] $links Action links.
 * @return string[]
 */
function action_links( $links ) {
	array_unshift(
		$links,
		'<a href="' . esc_url( admin_url( 'options-general.php?page=' . PAGE ) ) . '">' . esc_html__( 'Settings', 'wp-login-hardening' ) . '</a>'
	);
	return $links;
}
