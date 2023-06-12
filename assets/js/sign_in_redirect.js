jQuery('#loginform').ready(function ($) {
    $('<div class="create-account-box" style="margin-top: 5px"> <a class="ct-button" href="https://konto.rpi-virtuell.de/registrieren/?ref_service=' + location.href + '">RPI Konto erstellen</a> </div>').insertAfter($('#loginform'));
});
