

jQuery('#loginform').ready(function ($) {
    if (location.href === 'https://test.rpi-virtuell.de/wp-login.php ')
        $('<div class="create-account-box" style="margin-top: 5px"> <a class="ct-button" href="https://konto.rpi-virtuell.de/registrieren/?ref_service=' + location.origin + '">RPI Konto erstellen</a> </div>').insertAfter($('#loginform'));
    else
        $('<div class="create-account-box" style="margin-top: 5px"> <a class="ct-button" href="https://konto.rpi-virtuell.de/registrieren/?ref_service=' + location.href + '">RPI Konto erstellen</a> </div>').insertAfter($('#loginform'));
});