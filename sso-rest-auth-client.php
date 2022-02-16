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
        add_filter('registration_errors', array($this, 'remote_user_exists'), 10, 3);
        add_action('admin_menu', array($this, 'add_invite_user_option_page'));
        add_action('user_new_form_tag', array($this, 'redir_new_user'), 999);
        add_action('wp_ajax_search_user', 'ajax_search_user');
    }

    public function remote_user_exists(WP_Error $error, $sanitized_user_login, $user_email)
    {
        if (!empty($sanitized_user_login) && !empty($user_email)) {
            $url = 'https://test.rpi-virtuell.de/wp-json/sso/v1/remote_user_exists';
            $response = wp_remote_post($url, array(
                'method' => 'POST',
                'body' => array(
                    'sanitized_user_login' => $sanitized_user_login,
                    'user_email' => $user_email
                )));
            $response = json_decode(wp_remote_retrieve_body($response));
            if (is_wp_error($response)) {
                return $response;
            } elseif ($response->success) {
                return new WP_Error('User Exists', 'This User already exists'); //TODO: Hier sollte ggf. null returned werden
            } else {
                return $error;
            }
        } else {
            return new WP_Error('Missing Parameters', 'Required Parameters are missing!');
        }
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
                )));

            $response = json_decode(wp_remote_retrieve_body($response));
            if (!is_wp_error($response)) {
                if ($response->success) {
                    if ($user = get_user_by('login', $username)) {
                        if (is_multisite() && !is_user_member_of_blog($user->ID, get_current_blog_id())) {
                            add_user_to_blog(get_current_blog_id(), $user->ID, get_option('default_role'));
                        }
                        return $user;
                    } elseif ($user = get_user_by('email', $username)) {
                        if (is_multisite() && !is_user_member_of_blog($user->ID, get_current_blog_id())) {
                            add_user_to_blog(get_current_blog_id(), $user->ID, get_option('default_role'));
                        }
                        return $user;
                    } else {
                        $user_id = wp_insert_user(array(
                            'user_login' => $response->profile->user_login,
                            'first_name' => $response->profile->first_name,
                            'last_name' => $response->profile->last_name,
                            'user_pass' => wp_generate_password(8),
                            'display_name' => $response->profile->display_name,
                            'user_email' => $response->profile->user_email
                        ));
                        if (is_wp_error($user_id)) {
                            return $user_id->get_error_message();
                        } else {
                            return get_user_by('id', $user_id);

                        }
                    }
                } else {
                    return new WP_Error('NoResponse', 'No Response from Remote Login Server!');
                }

            } else {
                return $response->get_error_message();
            }

        } else {
            return new WP_Error('Missing Parameters', 'Required Parameters are missing!');
        }
    }

    function redir_new_user()
    {
        wp_redirect('/wp-admin/users.php?page=invite_user');
    }

    function add_invite_user_option_page()
    {
        add_users_page('invite_user', 'Nutzer einladen', 'manage_options', 'invite_user', array($this, 'init_invite_user_page'), 1);
    }

    function init_invite_user_page()
    {
        $search_input = '';

        if (isset($_POST['user-search-input'])) {
            $search_input = $_POST['user-search-input'];
        }
        ?>
        <form action="?page=invite_user" method="post">
            <div class="user-search-bar">
                <input type="text" id="user-search-input" name="user-search-input" value="<?php echo $search_input; ?>"
                       placeholder="Nutzer Suche">
                <button id="search-button" type="submit"> Suche</button>
            </div>
        </form>

        <?php
        if (!empty($search_input)) {
            $url = 'https://test.rpi-virtuell.de/wp-json/sso/v1/get_remote_users';
            $response = wp_remote_post($url, array(
                'method' => 'POST',
                'body' => array(
                    'search_query' => $search_input
                )));
            $response = json_decode(wp_remote_retrieve_body($response));
            if ($response->success) {
                foreach ($response->users as $user) {
                    ?>
                    <form action="?page=invite_user" method="post">
                        <div class="single-user-search-result">
                            <?php echo $user->avatar ?> <br>
                            Nutzername : <?php echo $user->user_login; ?> <br>
                            Name : <?php echo $user->first_name . ' ' . $user->last_name ?> <br>
                        </div>
                    </form>


                    <?php
                }
            }
        }


    }
}

new SsoRestAuthClient();

