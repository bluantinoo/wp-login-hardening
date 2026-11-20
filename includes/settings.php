<?php
/**
 * Settings: one option, constants that force it, and the page under Settings.
 *
 * @package WP_Login_Hardening
 */

namespace WP_Login_Hardening;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

const OPTION = 'wp_login_hardening';

const PAGE = 'wp-login-hardening';

/**
 * The switches, in the order the page shows them.
 *
 * @return array<string, bool> Block key => default.
 */
function defaults() {
	return [
		'enumeration'   => true,
		'login_errors'  => true,
		'xmlrpc'        => true,
		'roleless'      => true,
		'app_passwords' => false,
		'fail2ban'      => false,
	];
}

/**
 * Name of the constant that forces a block, e.g. WP_LOGIN_HARDENING_XMLRPC.
 *
 * @param string $block Block key.
 * @return string
 */
function constant_name( $block ) {
	return 'WP_LOGIN_HARDENING_' . strtoupper( $block );
}

/**
 * Whether a constant decides this block, so the page cannot change it.
 *
 * @param string $block Block key.
 * @return bool
 */
function is_forced( $block ) {
	return defined( constant_name( $block ) );
}

/**
 * Whether a block is on: the constant if defined, else the stored option.
 *
 * @param string $block Block key.
 * @return bool
 */
function is_enabled( $block ) {
	$defaults = defaults();
	if ( ! array_key_exists( $block, $defaults ) ) {
		return false;
	}

	// Accounts without a role are normal on a network: a user can belong to
	// one site and not another, and dropping their session would log them out
	// of the whole network.
	if ( 'roleless' === $block && is_multisite() ) {
		return false;
	}

	if ( is_forced( $block ) ) {
		return (bool) constant( constant_name( $block ) );
	}

	$stored = get_option( OPTION, [] );
	return is_array( $stored ) && array_key_exists( $block, $stored ) ? (bool) $stored[ $block ] : $defaults[ $block ];
}

/**
 * Trusted proxies, from the constant or the stored option.
 *
 * @return string[] IP addresses and CIDR ranges.
 */
function trusted_proxies() {
	if ( defined( 'WP_LOGIN_HARDENING_TRUSTED_PROXIES' ) ) {
		$raw = (string) WP_LOGIN_HARDENING_TRUSTED_PROXIES;
	} else {
		$stored = get_option( OPTION, [] );
		$raw    = is_array( $stored ) && isset( $stored['trusted_proxies'] ) ? (string) $stored['trusted_proxies'] : '';
	}

	return parse_proxies( $raw )[0];
}

/**
 * Splits a list of proxies on commas, spaces and new lines.
 *
 * @param string $raw Raw list.
 * @return array{0: string[], 1: string[]} Valid entries, and the ones that are not.
 */
function parse_proxies( $raw ) {
	$valid   = [];
	$invalid = [];

	foreach ( preg_split( '/[\s,]+/', $raw, -1, PREG_SPLIT_NO_EMPTY ) as $entry ) {
		if ( Fail2ban\is_valid_range( $entry ) ) {
			$valid[] = $entry;
		} else {
			$invalid[] = $entry;
		}
	}

	return [ array_values( array_unique( $valid ) ), $invalid ];
}

/**
 * Labels and descriptions of the blocks.
 *
 * @return array<string, array{label: string, description: string}>
 */
function blocks() {
	return [
		'enumeration'   => [
			'label'       => __( 'Hide usernames', 'wp-login-hardening' ),
			'description' => __( 'Visitors who are not logged in get no user list from the REST API, no redirect from ?author=N to the author page, no author archives, and oEmbed shows the site instead of the author.', 'wp-login-hardening' ),
		],
		'login_errors'  => [
			'label'       => __( 'Same error for a wrong name and a wrong password', 'wp-login-hardening' ),
			'description' => __( 'An unknown username or email gets the message WordPress gives for a wrong password, so the login form no longer confirms which names exist.', 'wp-login-hardening' ),
		],
		'xmlrpc'        => [
			'label'       => __( 'Turn off XML-RPC', 'wp-login-hardening' ),
			'description' => __( 'No XML-RPC methods, pingbacks included, not even those added by other plugins, and the X-Pingback header and RSD link are removed. Leave it off if the site uses Jetpack, the WordPress mobile app or remote publishing. With it on, WooPayments and the WooCommerce mobile app lose the Jetpack connection, and a translation service connected to WPML can no longer deliver: set WPML\'s Translation pickup mode to "The site will fetch translations manually".', 'wp-login-hardening' ),
		],
		'roleless'      => [
			'label'       => __( 'Accounts without a role cannot log in', 'wp-login-hardening' ),
			'description' => __( 'Retired accounts and author-only accounts can keep their content: remove their role and they can never log in again, and sessions they already have stop working. Not available on multisite.', 'wp-login-hardening' ),
		],
		'app_passwords' => [
			'label'       => __( 'Turn off application passwords', 'wp-login-hardening' ),
			'description' => __( 'Application passwords let an app call the REST API with a password alone, which bypasses two-factor login. Leave them on if an integration uses them; WooCommerce REST API keys are a separate mechanism and keep working.', 'wp-login-hardening' ),
		],
		'fail2ban'      => [
			'label'       => __( 'Log attempts for fail2ban', 'wp-login-hardening' ),
			'description' => __( 'Writes a line for every failed login, password reset request and blocked attempt, in the format of the WP fail2ban plugin. Useful only if you run fail2ban on the server.', 'wp-login-hardening' ),
		],
	];
}

add_action( 'admin_menu', __NAMESPACE__ . '\\add_settings_page' );

/**
 * Adds Settings > Login Hardening.
 */
function add_settings_page() {
	add_options_page(
		__( 'Login Hardening', 'wp-login-hardening' ),
		__( 'Login Hardening', 'wp-login-hardening' ),
		'manage_options',
		PAGE,
		__NAMESPACE__ . '\\render_settings_page'
	);
}

add_action( 'admin_init', __NAMESPACE__ . '\\register_settings' );

/**
 * Registers the option with its sanitizer.
 */
function register_settings() {
	register_setting(
		PAGE,
		OPTION,
		[
			'type'              => 'array',
			'sanitize_callback' => __NAMESPACE__ . '\\sanitize_settings',
			'default'           => defaults(),
		]
	);
}

/**
 * Keeps known keys only. A block forced by a constant keeps its stored value:
 * its checkbox is disabled and never submitted.
 *
 * @param mixed $input Submitted value.
 * @return array
 */
function sanitize_settings( $input ) {
	$input  = is_array( $input ) ? $input : [];
	$stored = get_option( OPTION, [] );
	$stored = is_array( $stored ) ? $stored : [];
	$clean  = [];

	foreach ( defaults() as $block => $default ) {
		if ( is_forced( $block ) ) {
			$clean[ $block ] = array_key_exists( $block, $stored ) ? (bool) $stored[ $block ] : $default;
		} else {
			$clean[ $block ] = ! empty( $input[ $block ] );
		}
	}

	if ( defined( 'WP_LOGIN_HARDENING_TRUSTED_PROXIES' ) ) {
		$clean['trusted_proxies'] = isset( $stored['trusted_proxies'] ) ? (string) $stored['trusted_proxies'] : '';
	} else {
		$raw                      = isset( $input['trusted_proxies'] ) ? sanitize_textarea_field( (string) $input['trusted_proxies'] ) : '';
		list( $valid, $invalid )  = parse_proxies( $raw );
		$clean['trusted_proxies'] = implode( "\n", $valid );
		if ( $invalid ) {
			add_settings_error(
				OPTION,
				'invalid_proxies',
				/* translators: %s: comma-separated list of entries. */
				sprintf( __( 'Not IP addresses or ranges, left out: %s', 'wp-login-hardening' ), implode( ', ', $invalid ) )
			);
		}
	}

	return $clean;
}

/**
 * Number of users with no role on this site.
 *
 * @return int
 */
function count_roleless_users() {
	global $wpdb;

	// An empty role list is stored as a:0:{}; a user never given one has no row.
	return (int) $wpdb->get_var(
		$wpdb->prepare(
			"SELECT COUNT(*) FROM {$wpdb->users} u
			WHERE NOT EXISTS (
				SELECT 1 FROM {$wpdb->usermeta} m
				WHERE m.user_id = u.ID AND m.meta_key = %s AND m.meta_value NOT IN ( '', 'a:0:{}' )
			)",
			$wpdb->get_blog_prefix() . 'capabilities'
		)
	);
}

/**
 * Renders Settings > Login Hardening.
 */
function render_settings_page() {
	if ( ! current_user_can( 'manage_options' ) ) {
		return;
	}

	$blocks = blocks();
	$test   = get_transient( 'wp_login_hardening_test_' . get_current_user_id() );
	if ( false !== $test ) {
		delete_transient( 'wp_login_hardening_test_' . get_current_user_id() );
	}
	?>
	<div class="wrap">
		<h1><?php esc_html_e( 'Login Hardening', 'wp-login-hardening' ); ?></h1>

		<?php if ( is_array( $test ) ) : ?>
			<div class="notice <?php echo esc_attr( $test['ok'] ? 'notice-success' : 'notice-error' ); ?>"><p><?php echo esc_html( $test['message'] ); ?></p></div>
		<?php endif; ?>

		<form method="post" action="options.php">
			<?php settings_fields( PAGE ); ?>
			<table class="form-table" role="presentation">
				<?php foreach ( $blocks as $block => $info ) : ?>
					<?php
					$id       = 'wp-login-hardening-' . $block;
					$forced   = is_forced( $block );
					$disabled = $forced || ( 'roleless' === $block && is_multisite() );
					?>
					<tr>
						<th scope="row"><?php echo esc_html( $info['label'] ); ?></th>
						<td>
							<label for="<?php echo esc_attr( $id ); ?>">
								<input type="checkbox" id="<?php echo esc_attr( $id ); ?>" name="<?php echo esc_attr( OPTION . '[' . $block . ']' ); ?>" value="1" <?php checked( is_enabled( $block ) ); ?> <?php disabled( $disabled ); ?>>
								<?php esc_html_e( 'On', 'wp-login-hardening' ); ?>
							</label>
							<?php if ( $forced ) : ?>
								<p class="description">
									<?php
									printf(
										/* translators: %s: constant name. */
										esc_html__( 'Set by the %s constant.', 'wp-login-hardening' ),
										'<code>' . esc_html( constant_name( $block ) ) . '</code>'
									);
									?>
								</p>
							<?php endif; ?>
							<p class="description"><?php echo esc_html( $info['description'] ); ?></p>
							<?php if ( 'roleless' === $block && ! is_multisite() ) : ?>
								<?php $roleless = count_roleless_users(); ?>
								<?php if ( $roleless > 0 ) : ?>
									<p class="description">
										<?php
										printf(
											/* translators: 1: number of users, 2: link to the list of users without a role. */
											esc_html( _n( '%1$d user on this site has no role. %2$s', '%1$d users on this site have no role. %2$s', $roleless, 'wp-login-hardening' ) ),
											(int) $roleless,
											'<a href="' . esc_url( admin_url( 'users.php?role=none' ) ) . '">' . esc_html__( 'See them', 'wp-login-hardening' ) . '</a>'
										);
										?>
									</p>
								<?php endif; ?>
							<?php endif; ?>
						</td>
					</tr>
				<?php endforeach; ?>
			</table>

			<h2><?php esc_html_e( 'fail2ban', 'wp-login-hardening' ); ?></h2>
			<table class="form-table" role="presentation">
				<tr>
					<th scope="row"><?php esc_html_e( 'Destination', 'wp-login-hardening' ); ?></th>
					<td><?php render_destination(); ?></td>
				</tr>
				<tr>
					<th scope="row"><label for="wp-login-hardening-proxies"><?php esc_html_e( 'Trusted proxies', 'wp-login-hardening' ); ?></label></th>
					<td>
						<?php $proxies_forced = defined( 'WP_LOGIN_HARDENING_TRUSTED_PROXIES' ); ?>
						<textarea id="wp-login-hardening-proxies" name="<?php echo esc_attr( OPTION . '[trusted_proxies]' ); ?>" rows="4" cols="50" class="code" <?php disabled( $proxies_forced ); ?>><?php echo esc_textarea( implode( "\n", trusted_proxies() ) ); ?></textarea>
						<?php if ( $proxies_forced ) : ?>
							<p class="description">
								<?php
								printf(
									/* translators: %s: constant name. */
									esc_html__( 'Set by the %s constant.', 'wp-login-hardening' ),
									'<code>WP_LOGIN_HARDENING_TRUSTED_PROXIES</code>'
								);
								?>
							</p>
						<?php endif; ?>
						<p class="description"><?php esc_html_e( 'IP addresses or ranges (CIDR) of the reverse proxies or CDN in front of the site, one per line. Only requests that come from one of them are allowed to name the visitor\'s address in X-Forwarded-For. Leave it empty if the site is reached directly: trusting that header from anyone would let anyone get any address banned.', 'wp-login-hardening' ); ?></p>
					</td>
				</tr>
			</table>

			<?php submit_button(); ?>
		</form>

		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<input type="hidden" name="action" value="wp_login_hardening_test">
			<?php wp_nonce_field( 'wp_login_hardening_test' ); ?>
			<p>
				<?php submit_button( __( 'Write a test line', 'wp-login-hardening' ), 'secondary', 'submit', false ); ?>
				<span class="description"><?php esc_html_e( 'Writes "Login Hardening test line" to the destination above, even if logging is off, to check that it arrives. No filter counts it.', 'wp-login-hardening' ); ?></span>
			</p>
		</form>
	</div>
	<?php
}

/**
 * Says where log lines go, and whether a log file is usable.
 */
function render_destination() {
	$path = Fail2ban\log_file();

	if ( null === $path ) {
		echo '<p>' . esc_html__( 'System log (syslog), facility auth.', 'wp-login-hardening' ) . '</p>';
		echo '<p class="description">';
		printf(
			/* translators: %s: constant name. */
			esc_html__( 'To write to a file instead, define %s with its absolute path in wp-config.php. The file can only be set there.', 'wp-login-hardening' ),
			'<code>WP_LOGIN_HARDENING_FAIL2BAN_LOG</code>'
		);
		echo '</p>';
		return;
	}

	echo '<p><code>' . esc_html( $path ) . '</code></p>';
	$error = Fail2ban\log_file_error( $path );
	if ( null !== $error ) {
		echo '<p class="description" style="color:#b32d2e;">' . esc_html( $error ) . '</p>';
	}
}

add_action( 'admin_post_wp_login_hardening_test', __NAMESPACE__ . '\\handle_test' );

/**
 * Writes a test line and goes back to the settings page with the outcome.
 */
function handle_test() {
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_die( esc_html__( 'Sorry, you are not allowed to do that.', 'wp-login-hardening' ), 403 );
	}
	check_admin_referer( 'wp_login_hardening_test' );

	set_transient( 'wp_login_hardening_test_' . get_current_user_id(), Fail2ban\write_test(), MINUTE_IN_SECONDS );

	wp_safe_redirect( admin_url( 'options-general.php?page=' . PAGE ) );
	exit;
}
