<?php
/*
Plugin Name: WordPress Revised Login Module
Description: + Encrypted Login Cookies + Force Logout after 24 HRS + Custom Login Error Message + Hide WordPress Version
Author: Saad Irfan
Author URI: http://saadirfan.com
Version: 1.0
Copyright: Saad Irfan
*/




global $wp_version;

	if ( $wp_version < 3 )
		wp_die( __( 'This Plugin Requires WordPress 3+ or Greater: Activation Stopped!' ) );


	if ( get_option( 'secured_cookie_key' ) !== false ):

		define( 'SECURE_COOKIE_KEY', get_option( 'secured_cookie_key' ) );

	else:

    	$deprecated = null;
    	$autoload = 'no';

    	$new_key = generateRandomString();

    	add_option( 'secured_cookie_key', $new_key, $deprecated, $autoload );

		define( 'SECURE_COOKIE_KEY', $new_key );

	endif;

	function generateRandomString() {
    	$characters = '0123456789';
    	$randomString = '';
    	for ($i = 0; $i < 5; $i++) {
        	$randomString .= $characters[rand(0, strlen($characters) - 1)];
    	}
    	return $randomString;
	}

if ( !function_exists('wp_validate_auth_cookie') ) :
/**
 * Validates authentication cookie.
 *
 * The checks include making sure that the authentication cookie is set and
 * pulling in the contents (if $cookie is not used).
 *
 * Makes sure the cookie is not expired. Verifies the hash in cookie is what is
 * should be and compares the two.
 *
 * @since 2.5
 *
 * @param string $cookie Optional. If used, will validate contents instead of cookie's
 * @param string $scheme Optional. The cookie scheme to use: auth, secure_auth, or logged_in
 * @return bool|int False if invalid cookie, User ID if valid.
 */
function wp_validate_auth_cookie($cookie = '', $scheme = '') {
	if ( ! $cookie_elements = wp_parse_auth_cookie($cookie, $scheme) ) {
		do_action('auth_cookie_malformed', $cookie, $scheme);
		return false;
	}

	extract($cookie_elements, EXTR_OVERWRITE);

	$expired = $expiration;

	// Allow a grace period for POST and AJAX requests
	if ( defined('DOING_AJAX') || 'POST' == $_SERVER['REQUEST_METHOD'] )
		$expired += HOUR_IN_SECONDS;

	// Quick check to see if an honest cookie has expired
	if ( $expired < time() ) {
		do_action('auth_cookie_expired', $cookie_elements);
		return false;
	}

	$decrypted_user_id = $username - SECURE_COOKIE_KEY - date('DD');

	$user = get_userdata($decrypted_user_id); 

	if ( ! $user ) {
		do_action('auth_cookie_bad_username', $cookie_elements);
		return false;
	}

	$pass_frag = substr($user->user_pass, 8, 4);

	$key = wp_hash($username . $pass_frag . '|' . $expiration, $scheme);
	$hash = hash_hmac('md5', $username . '|' . $expiration, $key);

	if ( $hmac != $hash ) {
		do_action('auth_cookie_bad_hash', $cookie_elements);
		return false;
	}

	if ( $expiration < time() ) // AJAX/POST grace period set above
		$GLOBALS['login_grace_period'] = 1;

	do_action('auth_cookie_valid', $cookie_elements, $user);

	return $user->ID;
}
endif;

if ( !function_exists('wp_generate_auth_cookie') ) :
/**
 * Generate authentication cookie contents.
 *
 * @since 2.5
 * @uses apply_filters() Calls 'auth_cookie' hook on $cookie contents, User ID
 *		and expiration of cookie.
 *
 * @param int $user_id User ID
 * @param int $expiration Cookie expiration in seconds
 * @param string $scheme Optional. The cookie scheme to use: auth, secure_auth, or logged_in
 * @return string Authentication cookie contents
 */
function wp_generate_auth_cookie($user_id, $expiration, $scheme = 'auth') {
	$user = get_userdata($user_id);


	$encrypted_user_id = SECURE_COOKIE_KEY + $user_id + date('DD');

	$pass_frag = substr($user->user_pass, 8, 4);

	$key = wp_hash($encrypted_user_id . $pass_frag . '|' . $expiration, $scheme); 
	$hash = hash_hmac('md5', $encrypted_user_id . '|' . $expiration, $key);

	$cookie = $encrypted_user_id . '|' . $expiration . '|' . $hash; 

	return apply_filters('auth_cookie', $cookie, $user_id, $expiration, $scheme);
}
endif;

/* ------------------------- */
// Custom Error Messages
function login_error_messages( $message ) {
    global $errors;
    
    if (isset($errors->errors['empty_username']) || isset($errors->errors['empty_password']) || isset($errors->errors['invalid_username']) || isset($errors->errors['incorrect_password'])) :
        $message = __('<strong>ERROR</strong>: Invalid username/password.', 'rys') . ' ' .
        sprintf(('<a href="%1$s" title="%2$s">%3$s</a>?'),
        site_url('wp-login.php?action=lostpassword', 'rys'),
        __('Password Lost and Found', 'rys'),
        __('Lost Password', 'rys'));
    endif;    
    return $message;    
}
add_filter( 'login_errors', 'login_error_messages' );

/* ------------------------- */
//  Hide WordPress Version

function mywp_remove_version() {
	return '';
}
add_filter('the_generator', 'mywp_remove_version');

?>