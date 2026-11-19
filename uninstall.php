<?php
/**
 * Removes the settings and the state of the update checker when the plugin is
 * deleted, on every site of a network. A log file set with
 * WP_LOGIN_HARDENING_FAIL2BAN_LOG is left alone: it belongs to the server's
 * fail2ban setup.
 *
 * @package WP_Login_Hardening
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

if ( is_multisite() ) {
	foreach ( get_sites( [ 'fields' => 'ids', 'number' => 0 ] ) as $wp_login_hardening_site ) {
		switch_to_blog( $wp_login_hardening_site );
		delete_option( 'wp_login_hardening' );
		restore_current_blog();
	}
} else {
	delete_option( 'wp_login_hardening' );
}

delete_site_option( 'external_updates-wp-login-hardening' );
wp_clear_scheduled_hook( 'puc_cron_check_updates-wp-login-hardening' );
