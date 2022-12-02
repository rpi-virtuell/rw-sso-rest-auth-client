<?php
/**
 * Plugin Name:      rw sso REST Auth Client
 * Plugin URI:       https://github.com/rpi-virtuell/rw-sso-rest-auth-client
 * Description:      Client Authentication tool to compare Wordpress login Data with a Remote Login Server
 * Author:           Daniel Reintanz
 * Version:          1.2.11
 * Domain Path:     /languages
 * Text Domain:      rw-sso-client
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
        session_start();
        if (!defined('KONTO_SERVER')) {
            if (getenv('KONTO_SERVER'))
                // env var is set in apache2.conf
                define('KONTO_SERVER', getenv('KONTO_SERVER'));
            else
                // .htaccess Eintrag fehlt: SetEnv KONTO_SERVER "https://my-wordpress-website.com"
                wp_die('Environmental Var KONTO_SERVER is not defined');
        }
        add_filter('authenticate', array($this, 'check_credentials'), 999, 3);
        add_action('login_head', array($this, 'login_through_token'));
        add_action('wp_head', array($this, 'login_through_token'));
        add_action('wp_logout', array($this, 'remote_logout'),1);
        add_action('wp_head', array($this, 'remote_login'));
        add_action('admin_head', array($this, 'remote_login'));
        add_action('init', array($this, 'delete_token_on_login_success'));
        add_action('admin_menu', array($this, 'add_invite_user_user_page'), 999);
        add_action('user_new_form_tag', array($this, 'redir_new_user'), 999);
        add_action('init', array($this, 'redir_new_user'), 999);
        add_action('wp_ajax_search_user', 'ajax_search_user');
        add_action('wp_ajax_get_users_via_ajax', array($this, 'get_users_via_ajax'));
        add_action('wp_ajax_invite_user_via_ajax', array($this, 'invite_user_via_ajax'));
        register_activation_hook(__FILE__, array($this, 'create_failed_login_log_table'));
        register_deactivation_hook(__FILE__, array($this, 'delete_failed_login_log_table'));
        add_action('admin_notices', array($this, 'backend_notifier'));
        add_filter('lostpassword_url', function () {
            return KONTO_SERVER . '/wp-login.php?action=lostpassword';
        });
        add_filter('register_url', function () {
            return KONTO_SERVER . '/wp-login.php?action=register';
        });
        add_action('wp_enqueue_scripts', array($this, 'add_sso_client_js'));

    }

    public function add_sso_client_js()
    {
        wp_enqueue_script(
            'template_handling',
            plugin_dir_url(__FILE__) . '/assets/js/sign_in_redirect.js',
            array(),
            '1.0',
            true
        );
    }

    /**
     * Sends a backend Notification which checks if the table failed_login_log is present and notifies the user if it isn't
     * @since 1.0.1
     * @access public
     * @action admin_notices
     */
    public function backend_notifier()
    {

        global $wpdb;

        $table_name = $wpdb->base_prefix . 'failed_login_log';

        if (empty($wpdb->get_var("SHOW TABLES LIKE '$table_name';"))) {
            ?>
            <div class="notice notice-error is-dismissible">
                <p><?php _e('WARNING: TABLE ' . $table_name . " WAS NOT CREATED! PLEASE REACTIVATE THE PLUGIN : rw sso REST Auth Client "); ?> </p>
            </div>
            <?php
        }
    }

    /**
     * Create Table which logs failed login attempts on plugin activation
     * @since 1.0
     * @action plugin activation
     * @access public
     */
    public function create_failed_login_log_table()
    {
        global $wpdb;

        $table_name = $wpdb->base_prefix . 'failed_login_log';
        $charset_collate = $wpdb->get_charset_collate();

        $sql = "CREATE TABLE IF NOT EXISTS $table_name (
                `hash`  char(32) NOT NULL DEFAULT '' ,
                `last_login`  bigint(20) NULL ,
                `ip`  varchar(30) NULL DEFAULT '' ,
                `username`  varchar(36) NULL DEFAULT '' ,
                INDEX (`hash`)
                ) $charset_collate;";


        $wpdb->query($sql);
    }

    /**
     * Delete Table which logs failed login attempts on plugin deactivation
     * @since 1.0
     * @action plugin deactivation
     * @access public
     */
    public function delete_failed_login_log_table()
    {
        global $wpdb;

        $table_name = $wpdb->base_prefix . 'failed_login_log';

        $sql = "DROP TABLE IF EXISTS `$table_name`;";

        $wpdb->query($sql);
    }

    /**
     * Check if user (accessed via specific IP) has less than 4 login attempts or last lock is older than 20 Minutes old
     * @param $username
     * @return bool|WP_Error
     * @since 1.0
     * @action check_credentials
     */
    public function check_login_attempts($username)
    {
        $ip = $_SERVER['REMOTE_ADDR'];
        $hash = md5($username . $ip);
        global $wpdb;
        $versuche = $wpdb->get_var("SELECT count(*) FROM {$wpdb->base_prefix}failed_login_log WHERE hash = '{$hash}' and last_login > UNIX_TIMESTAMP()-(60*20)");
        if (intval($versuche) > 3) {
            $lastlogin = $wpdb->get_var("SELECT last_login FROM {$wpdb->base_prefix}failed_login_log WHERE hash = '{$hash}' ORDER BY last_login DESC LIMIT 1");
            $lastlogin -= time() - 1200;
            $lastlogin = intval($lastlogin / 60);

            return new WP_Error('max_invalid_logins', sprintf(__("The maximum amount of login attempts has been reached please wait %d minutes", 'rw-sso-client'), $lastlogin));
        } elseif (5 < $wpdb->get_var("SELECT count(*) FROM {$wpdb->base_prefix}failed_login_log WHERE ip = '$ip' and last_login > UNIX_TIMESTAMP()-(60*20)")) {
            return new WP_Error('max_invalid_logins', __("The maximum amount of login attempts has been reached!", 'rw-sso-client'));
        } else {
            return true;
        }
    }

    /**
     * Delete failed login attempts which are older than 20 Minutes
     * @since 1.0
     * @action check_credentials
     */
    public function cleanup_old_failed_login_attempts()
    {

        global $wpdb;

        $table_name = $wpdb->base_prefix . 'failed_login_log';

        $sql = "DELETE FROM `$table_name` WHERE last_login < UNIX_TIMESTAMP()-(60*20);";

        $wpdb->query($sql);

    }

    /**
     * Add a new failed login attempt
     * @param $username
     * @since 1.0
     * @action check_credentials
     */
    public function add_failed_login_attempt($username)
    {

        $ip = $_SERVER['REMOTE_ADDR'];
        $hash = md5($username . $ip);
        global $wpdb;

        $result = $wpdb->insert(
            $wpdb->base_prefix . 'failed_login_log',
            array(
                'hash' => $hash,
                'ip' => $ip,
                'username' => $username,
                'last_login' => time(),
            ),
            array(
                '%s',
                '%s',
                '%s',
                '%d',
            )
        );

    }

    /**
     * Logout the current user of the Konto server and get redirected back to the home_url
     * @since 1.0
     * @action wp_logout
     */
    public function remote_logout()
    {
        unset($_SESSION['sso_remote_user']);
        $token = $_SESSION['rw_sso_login_token'];
        unset($_SESSION['rw_sso_login_token']);

        wp_redirect(
                KONTO_SERVER .
                '/wp-login.php?action=remote_logout&login_token='. $token .
                '&redirect_to=' . home_url());
        die();
    }

    /**
     * Set the login token if a login token is set in meta data of the current user
     * @since 1.0
     * @action wp_head
     * @action admin_head
     */
    public function remote_login()
    {
        if (is_user_logged_in()) {
            $login_token = get_user_meta(get_current_user_id(), 'rw_sso_login_token', true);
            if (!empty($login_token)) {
                ?>
                <script src="<?php echo KONTO_SERVER . '?sso_action=login&login_token=' . $login_token . '&user_id=' . get_current_user_id() . '&domain=' . home_url() ?>">
                </script>
                <?php
            }

        }
    }

    /**
     * Check if SSO Service has confirmed login via login_token
     * @since 1.2.4
     * @action init
     */
    public function delete_token_on_login_success()
    {
        if ($_POST['action'] === 'sso_delete_token' && isset($_POST['user_id'])) {
            $token = get_user_meta($_POST['user_id'], 'rw_sso_login_token', true);
            if ($token === $_POST['login_token']) {
                delete_user_meta($_POST['user_id'], 'rw_sso_login_token');
            }
        }
    }

    /**
     * Login the user via login token provided via url and check its validity via REST call to the Konto server
     * @since 1.0
     * @action login_head
     */
    public function login_through_token()
    {

        if (is_user_logged_in() || isset($_SESSION['sso_remote_user'])) {
            return;
        }
        if (isset($_GET['rw_sso_login_token'])) {
            $login_token = $_GET['rw_sso_login_token'];
            $url = KONTO_SERVER . '/wp-json/sso/v1/check_login_token';
            $response = wp_remote_post($url, array(
                'method' => 'POST',
                'body' => array(
                    'login_token' => $login_token,
                )));
            $response = json_decode(wp_remote_retrieve_body($response));
            if (!is_wp_error($response)) {
                if (isset($response->success)) {
                    if ($response->success) {
                        $user = get_user_by('login', $response->user_login);

                        if (!$user && in_array($response->user_login, get_super_admins())) {
                            switch_to_blog(1);
                            $user = get_user_by('login', $response->user_login);
                            restore_current_blog();
                        }
                        if ($user) {
                            wp_set_current_user($user->ID);
                            wp_set_auth_cookie($user->ID);
                        } else {
                            $_SESSION['sso_remote_user'] = 'unknown';
                        }
                        $redirect_to = home_url();
                        wp_safe_redirect($redirect_to);
                        exit();
                    }
                }
            }
            die();
        } else {

            ?>
            <script src="<?php echo KONTO_SERVER . '?action=check_token' ?>">
            </script>
            <script>
                if (rw_sso_login_token) {
                    location.href = '?sso_action=login&rw_sso_login_token=' + rw_sso_login_token + '&redirect=' + encodeURI(location.href);
                }
            </script>
            <?php


        }

    }

    /**
     * Central Method to handle the main Single Sign On logic
     * @param $user
     * @param $username
     * @param $password
     * @return WP_Error|WP_User
     * @since 1.0
     * @action authenticate
     */
    public function check_credentials($user, $username, $password)
    {
        if (!empty($username) && !empty($password)) {
            $this->cleanup_old_failed_login_attempts();
            if (!is_wp_error($attempts = $this->check_login_attempts($username))) {
                $url = KONTO_SERVER . '/wp-json/sso/v1/check_credentials';
                $response = wp_remote_post($url, array(
                    'method' => 'POST',
                    'body' => array(
                        'username' => $username,
                        'password' => $password,
                        'origin_url' => home_url()
                    )));
                if (!is_wp_error($response)) {
                    $response = json_decode(wp_remote_retrieve_body($response));
                    if (isset($response->success)) {
                        if ($response->success) {
                            if ($user = get_user_by('login', $username)) {
                                update_user_meta($user->ID, 'rw_sso_login_token', $response->profile->login_token);
                               $_SESSION['rw_sso_login_token'] = $response->profile->login_token;
                                if (is_multisite() && !is_user_member_of_blog($user->ID, get_current_blog_id())) {
                                    add_user_to_blog(get_current_blog_id(), $user->ID, get_option('default_role'));
                                }
                                return $user;
                            } elseif ($user = get_user_by('email', $username)) {
                                update_user_meta($user->ID, 'rw_sso_login_token', $response->profile->login_token);
                                $_SESSION['rw_sso_login_token'] = $response->profile->login_token;
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
                                    return $user_id;
                                } else {
                                    update_user_meta($user_id, 'rw_sso_login_token', $response->profile->login_token);
                                    $_SESSION['rw_sso_login_token'] = $response->profile->login_token;
                                    return get_user_by('id', $user_id);
                                }
                            }

                        } else {
                            $this->add_failed_login_attempt($username);
                            return new WP_Error('Wrong credentials', __('Username or password is invalid', 'rw-sso-client'));
                        }
                    } else {
                        return new WP_Error('NoResponse', __('No Response from Remote Login Server! Please inform the Administrator!', 'rw-sso-client'));
                    }
                } else {
                    if (is_a($user, 'WP_User')) {
                        return $user;
                    }
                    return new WP_Error('NoResponse', __('No Response from Remote Login Server! Please inform the Administrator!', 'rw-sso-client'));
                }
            } else {
                return $attempts;
            }
        } else {
            return $user;
        }
    }

    /**
     * Redirect Users to the invite users page if user_new.php is accessed
     * @action user_new_form_tag
     * @since  1.0
     */
    function redir_new_user()
    {
        if (strpos($_SERVER['SCRIPT_FILENAME'], 'wp-admin/user-new.php') !== false)
            wp_redirect(home_url() . '/wp-admin/users.php?page=invite_user');
    }

    /**
     * Remove and Add new menu User "creation" pages
     * @action admin_menu
     * @since 1.0
     */
    function add_invite_user_user_page()
    {
        remove_submenu_page('users.php', 'user-new.php');
        add_users_page('invite_user', __('Invite User', 'rw-sso-client'), 'manage_options', 'invite_user', array($this, 'init_invite_user_page'), 1);
    }

    /**
     * Provide a Json with User data html
     * @action wp_ajax_get_users_via_ajax
     * @since 1.0
     */
    public function get_users_via_ajax()
    {
        $search_input = isset($_POST['search_input']) ? $_POST['search_input'] : '';
        $return = array('success' => false);
        if (!empty($search_input)) {
            $url = getenv("KONTO_SERVER") . '/wp-json/sso/v1/get_remote_users';
            $response = wp_remote_post($url, array(
                'method' => 'POST',
                'body' => array(
                    'search_query' => $search_input
                )));
            if (wp_remote_retrieve_response_code($response) < 400) {
                $response = json_decode(wp_remote_retrieve_body($response));
                if ($response->success) {
                    $return = array('success' => true, 'results' => array());
                    foreach ($response->users as $user) {
                        $return['results'][] = "<div class='single-user-search-result' id='$user->user_login'>
                                        <div class='single-user-avatar'> $user->avatar </div>
                                        <div class='single-user-detail'> Nutzername : $user->user_login <br> Name : " . $user->first_name . " " . $user->last_name . "</div>
                                    </div>";
                    }
                }
            }
        }
        wp_send_json($return);
        die();
    }

    /**
     * Creates a User which is provided via ajax and returns its id
     * @since 1.0
     * @action wp_ajax_invite_user_via_ajax
     */
    public function invite_user_via_ajax()
    {
        $return = array('success' => false);
        $target_user = isset($_POST['target_user']) ? $_POST['target_user'] : false;
        $role = isset($_POST['role']) ? $_POST['role'] : 'subscriber';
        $url = getenv("KONTO_SERVER") . '/wp-json/sso/v1/get_remote_user';
        $response = wp_remote_post($url, array(
            'method' => 'POST',
            'body' => array(
                'user_login' => $target_user
            )));
        if (wp_remote_retrieve_response_code($response) < 400) {
            $response = json_decode(wp_remote_retrieve_body($response));
            if ($response->success && $target_user) {
                if ($user = get_user_by('login', $target_user)) {
                    if (is_multisite() && !is_user_member_of_blog($user->ID, get_current_blog_id())) {
                        add_user_to_blog(get_current_blog_id(), $user->ID, $role);
                        $return = array('success' => true, 'multisite' => true);
                    }
                } else {
                    $user_id = wp_insert_user(array(
                        'user_login' => $response->user->user_login,
                        'first_name' => $response->user->first_name,
                        'last_name' => $response->user->last_name,
                        'user_pass' => wp_generate_password(8),
                        'display_name' => $response->user->display_name,
                        'user_email' => $response->user->user_email,
                        'role' => $role
                    ));
                    $return = array('success' => true, 'user_id' => $user_id);
                }
            }
        }
        wp_send_json($return);
        die();
    }

    /**
     * Provide HTML information for the construction of a new User Menu Page to invite Users of a Konto Server
     * @since 1.0
     * @action add_users_page
     */
    function init_invite_user_page()
    {

        ?>
        <style>
            .single-user-search-result {
                display: grid;
                margin: 10px;
                padding: 5px 10px;
                width: 300px;
                background: lightgrey;
                border-radius: 5px;
            }

            .single-user-search-result img {
                border-radius: 5px;
            }

            .single-user-search-result:hover {
                background: white;
            }

            .single-user-detail {
                font-size: 1.4em;
            }

            #results {
                margin-top: 30px;
                display: grid;
                grid-template-columns: 1fr 1fr;
            }

            .results-info {
                display: none;
            }

            h1 {
                margin-bottom: 20px !important;
            }

        </style>
        <div class="wrap">
            <h1>Nutzer hinzufügen</h1>

            <input id="suche" placeholder="Nutzername oder Email">
            <button id="search-button" type="button">Suchen</button>
            <p class="results-info">Gewünschten Nutzer auswählen</p>
            <div id="results">Ergebnisse</div>
            <div id="user_invite_form" style="display:none;">
                <input type="hidden" id="selected_user">
                <span id="selected_user_display"></span>
                <?php echo $this->prepare_role_html(); ?>
                <button type="button" id="invite_user">Nutzer anlegen</button>
            </div>
        </div>


        <script>

            // Script erst laden, wenn das Document vollständig ausgebout ist
            jQuery(document).ready(function ($) {

                //Ajax soll ausgelöst werden wenn im Input Feld geschrieben wird
                $(document).on('keyup', '#suche', function () {
                    if ($('#suche').val().length >= 4) {
                        remote_search()
                    }
                });
                $(document).on('click', '#search-button', function () {
                    remote_search()
                });

                function remote_search() {
                    //ajax anfrage via Javascript an server schicken
                    $.ajax({
                        type: 'POST',
                        url: ajaxurl,                    // ajaxurl: global wp var
                        data: {                          // daten die per POST an den Server geschickt werden sollen
                            action: 'get_users_via_ajax',  // ajax action @see line 11
                            search_input: $('#suche').val()
                        },

                        //Ajax anfrage hat geklappt
                        success: function (data, textStatus, XMLHttpRequest) { //erfolgreiche anfrage
                            if ($('#results') && data.success == true) {

                                $('#results').html(''); //Ausgabe in das div#results schreiben:
                                $('.results-info').show();

                                for (const result of data.results) {
                                    $('#results').append(result);

                                }
                            }
                        },

                        //Ajax anfrage hat nicht geklappt
                        error: function (XMLHttpRequest, textStatus, errorThrown) {
                            console.log(errorThrown);
                        }
                    });
                }

                $(document).on('click', '.single-user-search-result', function (e) {
                    $('#user_invite_form').show();
                    $('#selected_user').val(e.currentTarget.id);
                    $('.single-user-search-result').hide();
                    $('#' + $.escapeSelector(e.currentTarget.id)).show();
                    $('.results-info').hide();

                });

                $(document).on('click', '#invite_user', function () {
                    $.ajax({
                        type: 'POST',
                        url: ajaxurl,                    // ajaxurl: global wp var
                        data: {                          // daten die per POST an den Server geschickt werden sollen
                            action: 'invite_user_via_ajax',  // ajax action @see line 11
                            target_user: $('#selected_user').val(),
                            role: $('#role').val()
                        },

                        //Ajax anfrage hat geklappt
                        success: function (data, textStatus, XMLHttpRequest) { //erfolgreiche anfrage
                            if ($('#results') && data.success === true) {
                                $('#user_invite_form').hide();
                                $('#results').html($('#selected_user').val() + ' wurde erfolgreich hinzugefügt!');
                            }
                            if ($('#results') && data.success === false) {
                                $('#results').html($('#selected_user').val() + ' konnte nicht hinzugefügt werden!');
                            }
                        },

                        //Ajax anfrage hat nicht geklappt
                        error: function (XMLHttpRequest, textStatus, errorThrown) {
                            console.log(errorThrown);
                        }
                    });
                })
            });
        </script>

        <?php


    }

    /**
     * Provide HTML to display a dropdown with all roles of the WordPress server
     * @return string
     * @since 1.0
     * @action init_invite_user_page
     */
    private function prepare_role_html()
    {
        $return = '<label for="role">Rolle festlegen</label><select name="role" id="role">';
        $roles = wp_roles()->get_names();
        foreach ($roles as $role => $name) {
            $selected = '';
            if ($role == "subscriber")
                $selected = 'selected';
            $return .= '<option value="' . $role . '" ' . $selected . ' >' . $name . '</option>';
        }
        $return .= '</select> ';
        return $return;
    }
}


new SsoRestAuthClient();

