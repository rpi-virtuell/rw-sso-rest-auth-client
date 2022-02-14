<?php
/**
 * Plugin Name:      rw sso REST Auth Client
 * Plugin URI:       https://github.com/rpi-virtuell/rw-sso-rest-auth-client
 * Description:      Client Authentication tool to compare Wordpress login Data with a Remote Login Server
 * Author:           Daniel Reintanz
 * Version:          1.0.0
 * Licence:          GPLv3
 * GitHub Plugin URI: https://github.com/rpi-virtuell/rw-sso-rest-auth-client
 * GitHub Branch:     master
 */

class SsoRestAuthClient
{

    /**
     * Plugin constructor.
     *
     * @since   0.1
     * @access  public
     * @uses    plugin_basename
     * @action  sso_rest_auth_client
     */
    public function __construct()
    {
        add_action('wp_authenticate', array('SsoRestAuthClient', 'check_credentials'), 10, 2);
    }

    public function check_credentials($username, $password)
    {
        if (!empty($username) && !empty($password)) {
            $url = 'test.rpi-virtuell.de/sso/v1/check_credentials';
            $response = wp_remote_post($url, array(
                'method' => 'POST',
                'body' => array(
                    'username' => $username,
                    'password' => $password
                ),
            ));

            if (!is_wp_error($response) && $response["success"]) {
                if ($user = get_user_by('login', $username)) {
                    return $user;
                } elseif ($user = get_user_by('email', $username)) {
                    return $user;
                } else {
                    return wp_insert_user(array(
                        'user_login' => $response['profile']['user_login'],
                        'user_pass' => wp_generate_password(8),
                        'display_name' => $response['profile']['display_name'],
                        'user_email' => $response['profile']['email']
                    ));
                }
            } else {
                return $response->get_error_message();
            }

        } else {
            return new WP_Error('Missing Parameters', 'Required Parameters are missing!');
        }
    }
}
new SsoRestAuthClient();

