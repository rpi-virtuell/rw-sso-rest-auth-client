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
        add_action('wp_ajax_request_via_ajax', array($this, 'request_via_ajax'));
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

    function add_invite_user_user_page()
    {
        add_users_page('invite_user', 'Nutzer einladen', 'manage_options', 'invite_user', array($this, 'init_invite_user_page'), 1);
    }

    //Hier kommt die Ajaxanfrage an  (@see line 11)
    public
    function request_via_ajax()
    {

        //$_POST auswerten
        $search_input = isset($_POST['search_input']) ? $_POST['search_input'] : '';
        $return = array('results' => array());

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
                    array_push($return['results'],
                            "<div class='single-user-search-result'>",
                            "$user->avatar ", "<br>",
                            "Nutzername : $user->user_login", "<br>",
                            "Name : $user->first_name $user->last_name", "<br>",
                            "</div>");
                }
            }
        }

        //als json versenden
        wp_send_json($return);
        die();
    }


    function init_invite_user_page()
    {

        ?>
        <h1>Nutzer einladen</h1>
        <input id="suche" placeholder="Nutzername oder Email">
        <div id="results">Ergebnisse</div>


        <script>

            // Script erst laden, wenn das Document vollständig ausgebout ist
            jQuery(document).ready(function ($) {

                //Ajax soll ausgelöst werden wenn im Input Feld geschrieben wird
                $(document).on('keydown', '#suche', function () {
                    //ajax anfrage via Javascript an server schicken
                    $.ajax({
                        type: 'POST',
                        url: ajaxurl,                    // ajaxurl: global wp var
                        data: {                          // daten die per POST an den Server geschickt werden sollen
                            action: 'request_via_ajax',  // ajax action @see line 11
                            search_input: $('#suche').val()
                        },

                        //Ajax anfrage hat geklappt
                        success: function (data, textStatus, XMLHttpRequest) { //erfolgreiche anfrage

                            if ($('#results')) {

                                $('#results').html(''); //Ausgabe in das div#results schreiben:
                                for (const result of data.results) {

                                    $('#results').append(result + '<br>');

                                }
                            }
                        },

                        //Ajax anfrage hat nicht geklappt
                        error: function (XMLHttpRequest, textStatus, errorThrown) {
                            console.log(errorThrown);
                        }
                    });
                });
            });
        </script>
        <?php


    }
}

new SsoRestAuthClient();

