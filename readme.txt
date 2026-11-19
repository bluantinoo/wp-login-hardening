=== Login Hardening ===
Contributors: bluantinoo
Tags: security, login, user enumeration, xml-rpc, fail2ban
Requires at least: 6.5
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 2.0.0
License: GPL-2.0-or-later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Hides usernames, gives the same error for a wrong name and a wrong password, turns off XML-RPC, locks out accounts without a role, and logs attempts for fail2ban.

== Description ==

A brute force works best when it already knows the real usernames of a site and when the login form tells it which names exist. This plugin takes both away, and a few more things an attacker uses.

Six blocks, each with a checkbox in Settings > Login Hardening and a constant that forces it:

* Hide usernames (on): no user list from the REST API for visitors, no redirect from ?author=N, no author archives, no users in WordPress's sitemap, oEmbed attributed to the site.
* Same error for a wrong name and a wrong password (on), and roughly the same response time, on every form that logs in through WordPress, WooCommerce's included. Lost password and registration forms are not changed.
* Turn off XML-RPC (on), pingbacks included.
* Accounts without a role cannot log in (on): remove the role of a retired account and it can never be used again, existing sessions included. Not available on multisite.
* Turn off application passwords (off).
* Log attempts for fail2ban (off): failed logins, WooCommerce logins refused by a captcha, wrong application passwords, lost password requests and blocked probes, to syslog or to a file, in the format of the WP fail2ban plugin.

Filters and example jails for fail2ban, and the full documentation, are in the GitHub repository: https://github.com/bluantinoo/wp-login-hardening

= Constants =

WP_LOGIN_HARDENING_ENUMERATION, WP_LOGIN_HARDENING_LOGIN_ERRORS, WP_LOGIN_HARDENING_XMLRPC, WP_LOGIN_HARDENING_ROLELESS, WP_LOGIN_HARDENING_APP_PASSWORDS, WP_LOGIN_HARDENING_FAIL2BAN (true or false), WP_LOGIN_HARDENING_FAIL2BAN_LOG (absolute path of a .log file outside the web root), WP_LOGIN_HARDENING_TRUSTED_PROXIES (addresses or CIDR ranges).

== Installation ==

1. Upload the plugin folder to `/wp-content/plugins/`.
2. Activate it. Every block except application passwords and fail2ban logging is on from activation.
3. Check Settings > Login Hardening, especially the number of users without a role.

== Frequently Asked Questions ==

= Where do updates come from? =

From the GitHub releases of the plugin (https://github.com/bluantinoo/wp-login-hardening/releases), not from wordpress.org. They appear in Dashboard > Updates like any other plugin.

= My site shows author pages on purpose =

Turn off "Hide usernames": it redirects every author archive to the home page.

= Who is affected by "Accounts without a role"? =

Users with no role on the site. The settings page counts them and links to them. WooCommerce customers have the Customer role and are not affected.

= Do I need fail2ban? =

Only for the logging block, and it needs root on the server. The other blocks work anywhere.

= The site is behind Cloudflare =

List Cloudflare's ranges as trusted proxies, so the log has the visitor's address (the last entry of X-Forwarded-For, the one Cloudflare writes), and ban at the edge with fail2ban's Cloudflare action: an iptables ban blocks nothing when connections come from Cloudflare.

= Can I switch from WP fail2ban? =

Yes. The failed login lines are the same, with the same tag and facility, so its filters keep working. Mind that its wordpress-hard filter, usually run with maxretry 1, also counts the user enumeration lines.

== Changelog ==

= 2.0.0 =
* First public release, from three must-use plugins used on production sites: user enumeration and login errors (1.2.2), XML-RPC off, accounts without a role. New: settings page and constants, application passwords switch, logging for fail2ban.

== Upgrade Notice ==

= 2.0.0 =
First public release.
