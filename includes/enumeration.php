<?php
/**
 * Block 1: no usernames for visitors who are not logged in.
 *
 * A brute force that starts from the real usernames of a site already has half
 * of every credential. On one site, 30 days of failed logins (12,694) were
 * aimed at the real usernames, not at admin or test: they had been read from
 * the open REST users endpoint.
 *
 * @package WP_Login_Hardening
 */

namespace WP_Login_Hardening\Enumeration;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Hooks the block.
 */
function register() {
	/*
	 * Last, and it is not cosmetic. rest_pre_dispatch passes the return value
	 * down the chain, so a later callback can overwrite the refusal: ACF 6
	 * returns null there unconditionally at priority 10, and the endpoint
	 * answered 200 with the full user list while this filter looked correctly
	 * registered.
	 */
	add_filter( 'rest_pre_dispatch', __NAMESPACE__ . '\\block_rest_users', PHP_INT_MAX, 3 );
	add_filter( 'wp_sitemaps_add_provider', __NAMESPACE__ . '\\remove_users_sitemap', 10, 2 );
	add_action( 'wp', __NAMESPACE__ . '\\block_author_queries', 1 );
	add_filter( 'oembed_response_data', __NAMESPACE__ . '\\attribute_oembed_to_site' );
}

/**
 * The REST users endpoint answers anonymous callers with the full list of logins.
 *
 * Only anonymous requests are refused. Logged in users keep it, and they need
 * it: the block editor and several admin plugins call /wp/v2/users/me on
 * nearly every screen, so blocking the route outright breaks the backend
 * quietly. No capability check, or an integration authenticating as a low
 * privilege user would break for no gain: enumeration is an anonymous attack,
 * and whoever is already inside reads the same names from the Users screen.
 *
 * @param mixed            $result  Response so far.
 * @param \WP_REST_Server  $server  Server.
 * @param \WP_REST_Request $request Request.
 * @return mixed
 */
function block_rest_users( $result, $server, $request ) {
	if ( is_user_logged_in() ) {
		return $result;
	}

	// Case-insensitive: WordPress matches REST routes case-insensitively, so
	// /wp-json/WP/v2/Users reaches the same handler.
	if ( 0 !== stripos( $request->get_route(), '/wp/v2/users' ) ) {
		return $result;
	}

	do_action( 'wp_login_hardening_blocked', 'enumeration' );

	// A response, not a WP_Error. A single request turns a WP_Error from
	// rest_pre_dispatch into a response, but a sub-request of /batch/v1 hands
	// it as it is to rest_post_dispatch, where WordPress 7.1 type-hints
	// WP_REST_Response: an anonymous batch with POST /wp/v2/users was a fatal
	// error and a 500 instead of a 401.
	return rest_convert_error_to_response(
		new \WP_Error(
			'rest_user_cannot_view',
			__( 'Sorry, you are not allowed to list users.' ), // phpcs:ignore WordPress.WP.I18n.MissingArgDomain -- core string, translated in every locale.
			[ 'status' => 401 ]
		)
	);
}

/**
 * ?author=N is the other way in: WordPress answers the numeric ID with a
 * redirect to /author/<nicename>/, handing over the public slug of user N.
 * Author archives by slug go the same way, or a guessed slug could be
 * confirmed by the difference between an archive and a 404.
 *
 * Only ?author=N is reported to the log block. Archives by slug are linked
 * from bylines and visited by search engines: logging them would get crawlers
 * banned.
 *
 * Hooked on 'wp' at priority 1, not on template_redirect. An SEO plugin with
 * author archives switched off redirects real authors on its own, earlier:
 * Rank Math does it on 'wp' at priority 10, so ?author=1 got Rank Math's
 * redirect and ?author=9999 got this one. Two different answers are the same
 * oracle this rule exists to close; running first gives every ID, real or
 * not, the same reply.
 *
 * The check reads the query vars, not is_author(): for a made-up slug
 * WordPress has already run handle_404() by now, and set_404() resets every
 * is_* flag while leaving the query vars in place.
 */
function block_author_queries() {
	if ( is_admin() || is_user_logged_in() ) {
		return;
	}

	// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- presence check only.
	$by_id = isset( $_GET['author'] );
	if ( ! $by_id && ! get_query_var( 'author_name' ) && ! get_query_var( 'author' ) ) {
		return;
	}

	// With plain permalinks ?author=N is the ordinary byline link: not a probe.
	if ( $by_id && get_option( 'permalink_structure' ) ) {
		do_action( 'wp_login_hardening_blocked', 'enumeration' );
	}

	// 302: browsers and CDNs keep a 301, which would outlive the block.
	wp_safe_redirect( home_url( '/' ), 302 );
	exit;
}

/**
 * WordPress's own sitemap lists every author archive, slug included.
 *
 * @param \WP_Sitemaps_Provider|false $provider Provider.
 * @param string                      $name     Provider name.
 * @return \WP_Sitemaps_Provider|false
 */
function remove_users_sitemap( $provider, $name ) {
	return 'users' === $name ? false : $provider;
}

/**
 * oEmbed answers anyone with the name and author page of whoever wrote any
 * post, and it lives in its own namespace, so the REST rule does not reach it.
 *
 * The content is attributed to the site instead, which is what core does for
 * a post with no author, so the preview card stays complete and valid. Only
 * these two fields change: the endpoint keeps working, including the preview
 * WordPress builds when an internal URL is pasted into a post.
 *
 * @param array $data oEmbed response data.
 * @return array
 */
function attribute_oembed_to_site( $data ) {
	if ( isset( $data['author_name'] ) ) {
		$data['author_name'] = get_bloginfo( 'name' );
	}
	if ( isset( $data['author_url'] ) ) {
		$data['author_url'] = get_home_url();
	}
	return $data;
}
