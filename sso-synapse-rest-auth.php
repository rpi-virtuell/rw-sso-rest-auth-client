<?php
/**
 * Plugin Name:      RW SSO Synapse REST Auth
 * Plugin URI:       https://github.com/rpi-virtuell/rw-SSO-synapse-rest-auth
 * Description:      Authentication tool to compare Wordpress login Data with a Remote Login Server
 * Author:           Daniel Reintanz
 * Version:          1.0.0
 * Licence:          GPLv3
 * GitHub Plugin URI: https://github.com/rpi-virtuell/rw-sso-synapse-rest-auth
 * GitHub Branch:     master
 */

class SSOSynapseRESTAuth
{

    static public $api_endpoint = '_SSO-internal/identity/v1';

    static private $instance = NULL;

    /**
     * Plugin constructor.
     *
     * @since   0.1
     * @access  public
     * @uses    plugin_basename
     * @action  rw_remote_auth_server_init
     */
    public function __construct()
    {
        add_action('rest_api_init', 'register_SSOsynapse_rest_routes');
        add_action('init', array('SSOSynapseRESTAuth', 'add_endpoint'), 0);
    }


    /**
     * Creates an Instance of this Class
     *
     * @return  RW_Remote_Auth_Server
     * @since   0.1
     * @access  public
     */
    public static function get_instance()
    {
        if (null === self::$instance) {
            self::$instance = new self;
        }

        return self::$instance;
    }

    /**
     * Add API Endpoint
     *
     * @return void
     * @since   0.1
     * @access  public
     * @static
     */

    /*
     static public function add_endpoint()
     {
         add_rewrite_rule('^' . SSOSynapseRESTAuth::$api_endpoint . '/([^/]*)/?', 'wp-json/SSO-synapse/v1/$1', 'top');
         flush_rewrite_rules();
     } //TODO: Remove if unnecessary
     */

}

if (class_exists('SSOSynapseRESTAuth')) {
    add_action('plugins_loaded', array('SSOSynapseRESTAuth', 'get_instance'));
    add_action('wp_authenticate', array('SSOSynapseRESTAuthAPI', 'check_credentials'));
}

function register_SSOsynapse_rest_routes()
{
    $controller = new SSOSynapseRESTAuthAPI();
    $controller->register_routes();
}

class SSOSynapseRESTAuthAPI extends WP_REST_Controller
{

    /**
     * Register the routes for the objects of the controller.
     */
    public function register_routes()
    {
        $version = '1';
        $namespace = 'sso-synapse/v' . $version;
        $base = 'check_credentials';
        register_rest_route($namespace, '/' . $base, array(
            array(
                'methods' => 'POST',
                'callback' => array($this, 'handle_request'),
                'args' => array(
                    'page' => array(
                        'required' => false
                    ),
                    'per_page' => array(
                        'required' => false
                    ),
                ),
            ),
        ));
    }

    public function handle_request(WP_REST_Request $request)
    {

        $request = $request->get_body();
        $requestObj = json_decode($request);
        if (null === $requestObj) {
            $data = array('auth' => array("success" => false));
        } else {
            $user = $requestObj->user->id;
            $mxid = $user;
            $user = substr($user, 1, strpos($user, ':') - 1);
            $password = addslashes($requestObj->user->password);

            $LoginUser = self::check_credentials(null, $user, $password);
            if (!is_wp_error($LoginUser) && !empty($LoginUser)) {
                $data = array('auth' => array(
                    "success" => true,
                    "mxid" => $mxid,
                    "profile" => array(
                        "display_name" => $LoginUser->display_name,
                    ),
                ));
            } else {
                $data = array('auth' => array("success" => false));
            }
        }

        $response = new WP_REST_Response($data);

        $response->set_status(201);
        return $response;
    }

    public function check_credentials($string, $username, $password)
    {
        if (!empty($username) && !empty($password)) {
            $url = 'konto.rpi-virtuell.de/matrix-synapse/v/check_credentials';
            $response = wp_remote_post($url, array(
                'method' => 'POST',
                'body' => array(
                    'username' => $username,
                    'password' => $password
                ),
            ));
            if ($response["success"]) {
                if ($user = get_user_by('login', $username)) {
                    return $user;
                } else {
                    return wp_insert_user(array(
                        'user_login' => $username,
                        'user_pass' => $password,
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

