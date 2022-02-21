# RW-SSO-REST-AUTH-CLIENT

*A WordPress plugin that provides the client side 
functionality of a **S**ingle **S**ign **O**n (SSO) Network*

**Please Note: This Plugin requires REST Routes provided
by the [RW-SSO-REST-AUTH-SERVICE](https://github.com/rpi-virtuell/rw-sso-rest-auth-service)
Plugin**

---

[Installation](#Installation)

[Features](#Features)

---

## Installation

### 1. Setting the Service Server
The Plugin needs to know where to send its REST Calls.
This is achieved by providing an Environmental Variable: 
KONTO_SERVER

KONTO_SERVER should provide a URL 

>SetEnv KONTO_SERVER "https://my-wordpress-website.com"

## Features
This Plugin alters two Backend areas of a standard WordPress website

### 1. Login
If a user logs in via WP-Admin the Server will send a
REST call to a set Service Server which uses the [RW-SSO-REST-AUTH-SERVICE](https://github.com/rpi-virtuell/rw-sso-rest-auth-service)
Plugin to verify the login information provided by 
comparing it with its own User Database.

### 2. Creating new Users
A new options page will be available under the user tab.
This will give users with the right *"edit_users"*
the option to import users from the set Service Server.

### Download

[RW-SSO-REST-AUTH-SERVICE](https://github.com/rpi-virtuell/rw-sso-rest-auth-service)
