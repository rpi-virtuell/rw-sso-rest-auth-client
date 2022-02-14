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
        add_filter('authenticate', array($this, 'check_credentials'), 10, 3);
    }

    public function check_credentials($user, $username, $password)
    {
        if (!empty($username) && !empty($password)) {
            $url = 'https://test.rpi-virtuell.de/wp-json/sso/v1/check_credentials';
            $response = wp_remote_post($url, array(
                'method' => 'POST',
                'body' => array(
                    'username' => $username,
                    'password' => $password
                ),
            ));

            $response = json_decode(wp_remote_retrieve_body($response));
            if (!is_wp_error($response)) {
                if ($response->success)
                {
                    if ($user = get_user_by('login', $username)) {
                        //wp_set_password($password, $user->ID);
                        return $user;
                    } elseif ($user = get_user_by('email', $username)) {
                        return $user;
                    } else {
                        $user_id =  wp_insert_user(array(
                            'user_login' => $response->profile->user_login,
                            'first_name' => $response->profile->first_name,
                            'last_name' => $response->profile->last_name,
                            'user_pass' => wp_generate_password(8),
                            'display_name' => $response->profile->display_name,
                            'user_email' => $response->profile->user_email
                        ));
                        if (is_wp_error($user_id)){
                            return $user_id->get_error_message();
                        }else{
                            return get_user_by('id',$user_id);

                        }
                    }
                }
                else{
                    return new WP_Error('NoResponse', 'No Response from Remote Login Server!');
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

