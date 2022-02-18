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
        add_action('admin_menu', array($this, 'add_invite_user_user_page'));
        add_action('user_new_form_tag', array($this, 'redir_new_user'), 999);
        add_action('wp_ajax_search_user', 'ajax_search_user');
        add_action('wp_ajax_get_users_via_ajax', array($this, 'get_users_via_ajax'));
        add_action('wp_ajax_invite_user_via_ajax', array($this, 'invite_user_via_ajax'));
    }

    public function check_credentials($user, $username, $password)
    {
        if (!empty($username) && !empty($password)) {
            $url = getenv("KONTO_SERVER") . '/wp-json/sso/v1/check_credentials';
            $response = wp_remote_post($url, array(
                'method' => 'POST',
                'body' => array(
                    'username' => $username,
                    'password' => $password,
                    'origin_url' => home_url()
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

    function add_invite_user_user_page()
    {
        add_users_page('invite_user', 'Nutzer einladen', 'edit_users', 'invite_user', array($this, 'init_invite_user_page'), 1);
    }

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
                        array_push($return['results'],
                            "<div class='single-user-search-result' id='$user->user_login'>
                                        <div class='single-user-avatar'> $user->avatar </div>
                                        <div class='single-user-detail'> Nutzername : $user->user_login <br> Name : " . $user->first_name . " " . $user->last_name . "</div>
                                    </div>");
                    }
                }
            }
        }
        wp_send_json($return);
        die();
    }

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
                        add_user_to_blog(get_current_blog_id(), $user->ID, get_option('default_role'));
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

                                $('#results').html('Ist erfolgreich hinzugefügt worden!');
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

    private function prepare_role_html()
    {
        $return = '<label for="role">Rolle festlegen</label><select name="role" id="role">';
        $roles = wp_roles()->get_names();
        foreach ($roles as $role => $name) {
            $return .= '<option value="' . $role . '">' . $name . '</option>';
        }
        $return .= '</select> ';
        return $return;
    }
}


new SsoRestAuthClient();

