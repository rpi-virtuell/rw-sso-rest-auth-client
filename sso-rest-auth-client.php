<?php
/**
 * Plugin Name:      rw sso REST Auth Client
 * Plugin URI:       https://github.com/rpi-virtuell/rw-sso-rest-auth-client
 * Description:      Client Authentication tool to compare Wordpress login Data with a Remote Login Server
 * Author:           Daniel Reintanz
 * Version:          1.3.2
 * Domain Path:     /languages
 * Text Domain:      rw-sso-client
 * Licence:          GPLv3
 * GitHub Plugin URI: https://github.com/rpi-virtuell/rw-sso-rest-auth-client
 * GitHub Branch:     master
 */

define('RW_SSO_DEBUG_LOG', false);

class SsoRestAuthClient
{

    /**
     * @since   1.2.17
     * @var int  how many times should client try to login user at kontoserver after sucessfull autentification
     */
    protected $max_login_attemps = 2;

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
        /**
         * We need some Session vars for login / logout communication with the konto server
         * $_SESSION['rw_sso_login_token'] is the konto server login-token and should be deleted after logout
         * $_SESSION['rw_sso_remote_user'] is set when the account server is asked whether the current user is logged in
         */
        if (session_status() !== PHP_SESSION_ACTIVE) session_start();

        if (!defined('KONTO_SERVER')) {
            if (getenv('KONTO_SERVER'))
                // env var is set in apache2.conf
                define('KONTO_SERVER', getenv('KONTO_SERVER'));
            else
                // .htaccess Eintrag fehlt: SetEnv KONTO_SERVER "https://my-wordpress-website.com"
                wp_die('Environmental Var KONTO_SERVER is not defined');
        }

        add_action('admin_bar_menu', array($this, 'add_admin_bar_menu_buttons'), 500);
        add_action('init', array($this, 'toggle_rpi_maintenance_mode'));
        add_action('wp_head', array($this, 'force_rpi_maintenance_mode'));

        add_filter('authenticate', array($this, 'check_credentials'), 999, 3);
        add_action('init', array($this, 'login_through_token'));
        add_action('wp', array($this, 'redrive_remote_token'));
        add_action('login_init', array($this, 'redrive_remote_token'));
        add_action('wp_logout', array($this, 'remote_logout'), 1);
        add_action('set_current_user', array($this, 'remote_login'));
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

    public function add_admin_bar_menu_buttons(WP_Admin_Bar $admin_Bar)
    {
        $maintenance_button_id = 'rpi-enable-maintenance-mode';

        if ((is_multisite() && current_user_can('manage_network')) || (!is_multisite() && current_user_can('manage_options'))) {
            if (!file_exists(plugin_dir_path(__FILE__) . '.rpi-maintenance')) {
                $admin_Bar->add_menu(array(
                    'id' => $maintenance_button_id,
                    'parent' => null,
                    'group' => null,
                    'title' => '<span class="dashicons-admin-tools ab-icon"></span>',
                    'href' => wp_nonce_url(home_url() . '?maintenance=on'),
                    'meta' => [
                        'title' => 'Wartungsmodus inaktiv',
                    ]
                ));
            } else {
                $admin_Bar->add_menu(array(
                    'id' => 'rpi-disable-maintenance-mode',
                    'parent' => null,
                    'group' => null,
                    'title' => '<span style="background-color: red; padding: 5px; top: 0;" class="dashicons-admin-tools ab-icon"></span>',
                    'href' => wp_nonce_url(home_url() . '?maintenance=off'),
                    'meta' => [
                        'title' => 'Wartungsmodus aktiv',
                    ]
                ));
            }
        }

        $admin_Bar->add_menu(array(
            'id' => 'menu-id',
            'parent' => null,
            'group' => null,
            'title' => 'Hilfe',
            'href' => 'https://hilfe.rpi-virtuell.de/',
            'meta' => [
                'title' => 'Zur Hilfeseite von rpi-virtuell',
            ]
        ));

    }

    public function toggle_rpi_maintenance_mode()
    {

        if (is_multisite() && wp_verify_nonce($_GET['_wpnonce']) && current_user_can('manage_network') && $_GET['maintenance'] === 'on') {
            if (!file_exists(plugin_dir_path(__FILE__) . '.rpi-maintenance'))
                file_put_contents(plugin_dir_path(__FILE__) . '.rpi-maintenance', 'wartungsmodus');
        } elseif (wp_verify_nonce($_GET['_wpnonce']) && current_user_can('manage_options') && $_GET['maintenance'] === 'on') {
            if (!file_exists(plugin_dir_path(__FILE__) . '.rpi-maintenance'))
                file_put_contents(plugin_dir_path(__FILE__) . '.rpi-maintenance', 'wartungsmodus');
        }


        if (is_multisite() && wp_verify_nonce($_GET['_wpnonce']) && current_user_can('manage_network') && $_GET['maintenance'] === 'off') {
            if (file_exists(plugin_dir_path(__FILE__) . '.rpi-maintenance')) {
                unlink(plugin_dir_path(__FILE__) . '.rpi-maintenance');
            }
        } elseif (wp_verify_nonce($_GET['_wpnonce']) && current_user_can('manage_options') && $_GET['maintenance'] === 'off') {
            if (file_exists(plugin_dir_path(__FILE__) . '.rpi-maintenance')) {
                unlink(plugin_dir_path(__FILE__) . '.rpi-maintenance');
            }
        }
    }

    public
    function force_rpi_maintenance_mode()
    {
        if (file_exists(plugin_dir_path(__FILE__) . '.rpi-maintenance') && !current_user_can('manage_options')) {
            include_once plugin_dir_path(__FILE__) . 'templates/sso_maintenance.php';
            wp_die();
        }
    }

    public
    function add_sso_client_js()
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
    public
    function backend_notifier()
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
    public
    function create_failed_login_log_table()
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
    public
    function delete_failed_login_log_table()
    {
        global $wpdb;

        $table_name = $wpdb->base_prefix . 'failed_login_log';

        $sql = "DROP TABLE IF EXISTS `$table_name`;";

        $wpdb->query($sql);
    }

    /**
     * After user succesfully loggedin at client, he should be real loggedin at the konto server too.
     * For this he will be redirect to konto server with the url params sso_action=login ...
     * and the token, he got during the remote authentication process from the konto server
     * After succesfully loggedin at konto server, the user will be redirected back to his current client site
     *
     * @since 1.0
     * @action wp_head
     * @action set_current_user
     */
    public
    function remote_login()
    {
        if (is_user_logged_in() && !wp_doing_ajax()) {

            if (session_status() !== PHP_SESSION_ACTIVE) session_start();
            //$login_token = get_user_meta(get_current_user_id(), 'rw_sso_login_token', true);
            //if (!empty($login_token) && !isset($_SESSION['rw_sso_login_token'])) {
            //var_dump($_SESSION['rw_sso_login_token'],$_SESSION['rw_sso_remote_login_attemps']);


            if (!isset($_SESSION['rw_sso_remote_login_attemps'])) {
                $_SESSION['rw_sso_remote_login_attemps'] = 0;
            }
            if (intval($_SESSION['rw_sso_remote_login_attemps']) < $this->max_login_attemps && isset($_SESSION['rw_sso_login_token'])) {


                if ($_SESSION['rw_sso_remote_login_attemps'] === 0) {
                    /**
                     * after successful remote login, we need to tell the client not to make any further login attempts.
                     * The account server has no access to the browser bound $__SESSION.
                     * Therefore we write the login token in the user meta,
                     * which we can also access from the account server via wp_remote.
                     * @see delete_token_on_login_success()
                     */
                    update_user_meta(get_current_user_id(), 'rw_sso_login_token', $_SESSION['rw_sso_login_token']);
                    $this->log('remote_login_prepare', 'update_user_meta:' . $_SESSION['rw_sso_login_token']);

                }

                $_SESSION['rw_sso_remote_login_attemps']++;

                $this->log('remote_login', 'dry:' . $_SESSION['rw_sso_remote_login_attemps']);

                $url = KONTO_SERVER . '?sso_action=login&login_token=' . $_SESSION['rw_sso_login_token'] .
                    '&user_id=' . get_current_user_id() . '&domain=' . urlencode(home_url()) .
                    '&redirect_to=' . urlencode(site_url() . $_SERVER['PATH_INFO']);


                $token = get_user_meta(get_current_user_id(), 'rw_sso_login_token', true);
                /**
                 * nach erfolgreichem remote login wird der token aus den user meta gelöscht
                 * @see delete_token_on_login_success()
                 */
                if (!empty($token)) {
                    $this->log('remote_login_redirect', 'token:' . $_SESSION['rw_sso_login_token']);
                    echo "<script>top.location.href='$url'</script>";
                    //wp_redirect($url);
                    die();
                }

            }
        }
    }

    /**
     * @param $cmd
     * @param $param1
     * @param $param2
     * @param $param3
     * @param $user_id
     *
     * @return void
     * @since v1.2.17
     *
     * prints helpfull log entries in /tmp/sso.log if RW_SSO_DEBUG_LOG == true
     * use:   tail -f /tmp/sso.log
     *
     */
    public
    function log($cmd, $param1 = '', $param2 = '', $param3 = '', $user_id = 0)
    {

        if (RW_SSO_DEBUG_LOG === true) {

            if (get_current_user_id() > 0) {
                $user = wp_get_current_user()->user_login;
            } elseif ($user_id > 0) {
                $user = get_userdata($user_id)->user_login;
            } else {
                $user = 'anon';
            }

            $str = "\n" . $cmd;
            $str .= empty($param1) ? '' : '|' . $param1;
            $str .= empty($param2) ? '' : '|' . $param2;
            $str .= empty($param3) ? '' : '|' . $param3;

            $str .= "\n....." . home_url() . '|sessId:' . session_id() . '|' . $user;

            $str .= "\n";
            file_put_contents('/tmp/sso.log', $str, FILE_APPEND);
        }


    }

    /**
     * Logout the current user of the Konto server and get redirected back to the home_url
     * @since 1.0
     * @action wp_logout
     */
    public
    function remote_logout()
    {
        $token = $_SESSION['rw_sso_login_token'];
        unset($_SESSION['rw_sso_login_token']);
        unset($_SESSION['rw_sso_remote_login_attemps']);
        unset($_SESSION['sso_remote_user_check']);

        $this->log('remote_logout', 'SESSION:' . json_encode($_SESSION));

        wp_redirect(
            KONTO_SERVER . '/wp-login.php' .
            '?sso_action=remote_logout&login_token=' . $token .
            '&redirect_to=' . urlencode(home_url()));
        die();
    }

    /**
     * Check if SSO Service has confirmed login via login_token
     * @since 1.2.4
     * @action init
     */
    public
    function delete_token_on_login_success()
    {
        if ($_POST['action'] === 'sso_delete_token' && isset($_POST['user_id'])) {
            $token = get_user_meta($_POST['user_id'], 'rw_sso_login_token', true);

            if ($token === $_POST['login_token']) {
                delete_user_meta($_POST['user_id'], 'rw_sso_login_token');
                $this->log('delete_token_on_login_success', 'token:' . $token, 'user_id:' . $_POST['user_id'], '', $_POST['user_id']);
            }

        }

    }

    /**
     * If a user is logged in on the konto server and visits a customer site where he is not logged in,
     * he should be automatically logged in on the customer site as well.
     * STEPS:
     * 1. redirect to konto server: sso_action=check_token (fetch login token if exists)
     * 2. redirect back with the url param rw_sso_login_token=xyz (empty if user not logged in at konto server)
     * 3 if the user exists on the client login on client site
     *   or set $_SESSION['sso_remote_user'] : stops further requests
     *
     * @since 1.0
     * @action wp (init seems too early)
     */
    public
    function login_through_token()
    {
        if (session_status() !== PHP_SESSION_ACTIVE) session_start();

        if (!is_user_logged_in() && !isset($_SESSION['sso_remote_user'])) {

            if (isset($_GET['rw_sso_login_token']) && isset($_GET['sso_action']) && $_GET['sso_action'] == 'login_through_token') {


                $login_token = $_GET['rw_sso_login_token'];

                $this->log('login_through_token', 'got_token:' . $login_token);
                if (empty($login_token)) {
                    $_SESSION['sso_remote_user'] = 'unknown'; //prevent infinite loop
                    wp_safe_redirect(site_url() . $_SERVER['PATH_INFO']);
                    die();
                }
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
                                // set Session rw_sso_login_token  for remote logout
                                $_SESSION['rw_sso_login_token'] = $login_token;
                                $_SESSION['rw_sso_remote_login_attemps'] = $this->max_login_attemps;
                                $this->log('login_through_token', 'success|token:' . $_SESSION['rw_sso_login_token']);
                            } else {
                                $_SESSION['sso_remote_user'] = 'unknown';
                            }
                            $redirect_to = site_url() . $_SERVER['PATH_INFO'];
                            wp_safe_redirect($redirect_to);
                            exit();
                        }
                    }
                }
                die();
            }
        } elseif (is_user_logged_in()) {
            unset($_SESSION['sso_remote_user']);

        } else {
            if (isset($_GET['rw_sso_login_token']) && isset($_GET['sso_action'])) {
                wp_safe_redirect(site_url() . $_SERVER['PATH_INFO']);
                die();

            }

        }

    }

    /**
     * redirects to Konto server one time
     * fetch a login-token from the current Konto server user (string or empty if not logged in)
     * konto Server redirects back to client with param rw_sso_login_token
     * @see login_through_token() method
     * actions: wp, login_init;
     */
    public
    function redrive_remote_token()
    {
        if (!is_user_logged_in() && isset($_COOKIE['PHPSESSID']) && strLen($_COOKIE['PHPSESSID']) > 30) {
            if (is_front_page() || is_home() || is_login()) {

                ///bot|spider|crawl|scanner/i
                $agent = $_SERVER['HTTP_USER_AGENT'];
                if (preg_match("/bot|spider|crawl|scanner|wordpress|wp|appletv|dalvik|roku|crkey|kindle|slurp|search|nintendo|xbox/i", $agent)) {
                    return;
                }

                if (session_status() !== PHP_SESSION_ACTIVE) session_start();

                $redir_url = KONTO_SERVER . '?sso_action=check_token&redirect_to=' . site_url() . $_SERVER['PATH_INFO'];
                if (!isset($_SESSION['sso_remote_user_check'])) {
                    $_SESSION['sso_remote_user_check'] = 'check'; //prevent infinite redirection loop
                    $this->log('redrive_remote_token', 'sso_remote_user_check:' . $_SESSION['sso_remote_user_check']);
                    wp_redirect($redir_url);
                    die();
                }

            }
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
    public
    function check_credentials($user, $username, $password)
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

                            if (session_status() !== PHP_SESSION_ACTIVE) session_start();
                            $this->log('check_credentials', 'token:' . $response->profile->login_token, 'username:' . $username);
                            if ($user = get_user_by('login', $username)) {
                                //update_user_meta($user->ID, 'rw_sso_login_token', $response->profile->login_token);
                                $_SESSION['rw_sso_login_token'] = $response->profile->login_token;
                                if (is_multisite() && !is_user_member_of_blog($user->ID, get_current_blog_id())) {
                                    add_user_to_blog(get_current_blog_id(), $user->ID, get_option('default_role'));
                                }
                                return $user;
                            } elseif ($user = get_user_by('email', $username)) {
                                //update_user_meta($user->ID, 'rw_sso_login_token', $response->profile->login_token);
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
                                    //update_user_meta($user_id, 'rw_sso_login_token', $response->profile->login_token);
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
                        $this->log('check_credentials-lokal-login');
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
     * Delete failed login attempts which are older than 20 Minutes
     * @since 1.0
     * @action check_credentials
     */
    public
    function cleanup_old_failed_login_attempts()
    {

        global $wpdb;

        $table_name = $wpdb->base_prefix . 'failed_login_log';

        $sql = "DELETE FROM `$table_name` WHERE last_login < UNIX_TIMESTAMP()-(60*20);";

        $wpdb->query($sql);

    }

    /**
     * Check if user (accessed via specific IP) has less than 4 login attempts or last lock is older than 20 Minutes old
     * @param $username
     * @return bool|WP_Error
     * @since 1.0
     * @action check_credentials
     */
    public
    function check_login_attempts($username)
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
     * Add a new failed login attempt
     * @param $username
     * @since 1.0
     * @action check_credentials
     */
    public
    function add_failed_login_attempt($username)
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
    public
    function get_users_via_ajax()
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
    public
    function invite_user_via_ajax()
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
    private
    function prepare_role_html()
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


