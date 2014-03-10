#BasicAuthenticator Implementation for PHP

##Description
This is a PHP implementation of the [UMN Community Shibboleth BasicAuthenticator
API](https://github.umn.edu/umn-community-shib/umn-shib-api).

It is intended as an easy to use interface to construct Shibboleth SP
login/logout URLs, redirect through the Shibboleth SessionInitiator, and access
standard attributes.

The implementation, like the API which describes it, is intended to provide a
baseline set of common functions coupled with access to the standard set of
Shibboleth attributes Identity Management exposes to all service providers. It 
has been designed to be easily extensible, allowing you to add features specific
to your academic or departmental unit.

## Prerequisites
- PHP 5.3 or later (depends on PHP 5.3 namespaces)
- A server with the Shibboleth Native SP installed, configured, and running.

This library will make certain default assumptions about the Shibboleth SP
environment, but can generally be configured to behave differently.  

## Installation
Preferably you should be installing via [Composer](http://getcomposer.org).

Add the following to your project's `composer.json` to attach it to this repo on
`github.umn.edu` and load the package.

```json
"repositories": [
    {
        "type": "vcs",
        "url": "git@github.umn.edu:umn-community-shib/umn-shib-php.git"
    }
],
"require": {
    "umn-community-shib/basic-authenticator": "~1.0.0"
}
```

If you are not using Composer, you can still use it by manually including the
necessary files. _This is not really supported, but will work if you manually
`include/require` all the necessary files_.

require_once '/path/to/umnshib/BasicAuthenticator.php';
// If you plan to use user mocking, you'll need this too.
require_once '/path/to/umnshib/Mock/UserFactory.php';

## Basic Object-oriented or Procedural Usage
Like many modern PHP libraries aiming to provide backward compatibility and ease
of integration into almost any PHP application, this one provides API access
either via a fully object-oriented interface, or via a slightly limited
procedural interface.

Internally, the procedural interface merely wraps the object-oriented one, and
must discard some functionality where it is unable to maintain state.

```php
use UMNShib\Basic\BasicAuthenticator;

// Example Object-Oriented instantiation and redirect to login:
$umnshib = new BasicAuthenticator();
if (!$umnshib->hasSession()) {
  $umnshib->redirectToLogin($loginOptions);
}

// Comparable example using the procedural interface
if (!umnshib_hasSession()) {
  umnshib_redirectToLogin();
}
```

The examples in the previous section demonstrate usage when you may have some custom logic to perform. It
is also possible to make a single call to either retrieve all known attributes
as an array or redirect to a login session:

```php
use UMNShib\Basic\BasicAuthenticator;

// Object-oriented style
$umnshib = new BasicAuthenticator();
$attributes = $umnshib->getAttributesOrRequestLogin();

// Procedural style
$attributes = umnshib_getAttributesOrRequestLogin();
```

## Configuration
### Shibboleth.sso handler URL
Most commonly (by default), the Shibboleth SP handler URL is located at
`/Shibboleth.sso` and this library expects to find it there unless otherwise
instructed.

```php
$umnshib->setHandlerURL('/some/other/path/Shibboleth.sso');
```

### Shibboleth environment or HTTP headers
If your server is configured to with `ShibUseHeaders on`, you will need to set
it up accordingly via `setAttributeAccessMethod()`. By default it will retrieve
attributes from the web server environment rather than HTTP headers.

```php
// Object-oriented setup
$umnshib->setAttributeAccessMethod(\UMNShib\Basic\BasicAuthenticator::UMN_ATTRS_FROM_HEADERS);
```

When using the procedural interface, functions requiring access to Shibboleth
attributes include a `$useHeaders` boolean parameter, which defaults to `false`.

```php
// Procedural example retrieving attributes from HTTP headers,
// pass true as the $useHeaders parameter0
$uid = umnshib_getAttributeValue('uid', true);
```

### Login / Logout Options
Several options are available to facilitate features like passive
authentication, 2-factor (MKey) logins, return URLs, forced authentication, or
alternate entity ID.

Methods like `buildLoginURL(), buildLogoutURL(), redirectToLogin(),
redirectToLogout(), getAttributesOrRequestLogin()` accept an array paramter
of options. It should be an associative array of `'key' => 'value'` pairs
corresponding to the options documented on the [UMN Community Shibboleth API
wiki](https://github.umn.edu/umn-community-shib/umn-shib-api/wiki/UMN-Shibboleth-Basic-API) for `buildLoginURL()` and `buildLogoutURL()`.

#### Login Options
Available options:

- `target` Return URL
- `IdPEntityID` Alternate IdP entity ID
- `forceAuthn` require a login/password screen
- `passive` permit `isPassive`
- `authnContextClassRef` Requested authentication type
- `mkey` Shortcut to set `authnContextClassRef` appropriately for MKey

##### Examples
Retrieve a login URL forcing a login screen even if the user already has a
session, using 2-factor (MKey):

```php
$url = buildLoginURL(array('forceAuthn' => true, 'mkey' => true));
```

Redirect through the login passively (no login screen) and specify the return
URL:

```php
redirectToLogin(array(
  'passive' => true,
  'target' => 'https://example.com/passive/login/endpoint'
));
```

Login using the test IdP:

```php
$url = buildLoginURL(array('IdPEntityID' => BasicAuthenticator::UMN_TEST_IDP_ENTITY_ID));
```
#### Logout Options
- `return` Return URL
- `logoutFromIdP` Complete a logout from the IdP
- `IdPLogoutURL` Alternate logout URL for IdP

##### Examples
Logout from the IdP, and specify the return URL:

```php
buildLogoutURL(array(
  'logoutFromIdP' => true,
  'return' => 'https://example.com/logout/endpoint'
));
```

#### Passing options to the constructor on instantiation
Login options may also be passed to the constructor:

```php
// Options in the constructor
$umnshib = new BasicAuthenticator(
  // First param is array of login options
  array('forceAuthn' => true, 'target' => 'https://example.com/login/target'),
  // Second param is array of logout options
  array('logoutFromIdP' => true)
);
// And they are applied when building URLs...
$url = $umnshib->buildLoginURL();
```

## Testing and Mock Users
### Enabling mock users on the server
Mock users must be enabled in the server environment by the presence and truthy
value of the environment variable `UMNSHIB_ALLOW_MOCK_USER`.o

**DO NOT enable mock users on any system accessed by untrusted users!**

The variable may be set at runtime with an expression like:

```php
setenv('UMNSHIB_ALLOW_MOCK_USER', true);
```

Or ideally it could be set in the server itself, allowing test/production
environments proper segregation.  To set it with Apache `mod_rewrite`, use:

```apache
# Via mod_rewrite if you need to match complex conditions
RewriteEngine On
RewriteRule ^ - [E=UMNSHIB_ALLOW_MOCK_USER:true]
RewriteRule ^ - [E=UMNSHIB_MOCK_USER_FILE:/path/to/mock_users.php]

# Or via SetEnv if you don't need to do it conditionally
SetEnv UMNSHIB_ALLOW_MOCK_USER true
SetEnv UMNSHIB_MOCK_USER_FILE /path/to/mock_users.php
```

Note: `UMNSHIB_ALLOW_MOCK_USER` is processed via `filter_var()` to detect
"boolean-like" values. That means strings like "true, On, Yes, 1" will be `true`
while strings like `false, no, off, 0` and anything else will be `false`.

### Defining mock users
Mock users are defined in a PHP file, also pointed to by an environment
variable.  _PHP isn't a great option but it has no dependencies and is
relatively safe from accidental exposure by the web server. Of course, YAML or
JSON would be nicer, but let's stick with PHP for now..._

```php
setenv('UMNSHIB_MOCK_USER_FILE', '/path/to/mock_users.php');
// ... or use Apache mod_rewrite with the same pattern as described earlier...
```

The mock users definition be a PHP file from which you `return` an `array()` of
users.  The array must be associative, indexed by username (the `uid`
attribute value).  It then serves as a `key => value` list of other attributes
to set in the user's environment.

Note about `REMOTE_USER`: If your application expects the `REMOTE_USER` CGI
variable to be set to a value like `uid` or `eppn` per your server's Shibboleth
configuration, you must set `REMOTE_USER` in the mock user array. It won't be
set automatically.

```php
<?php
// Sample mock user file
// Must return an associative array
return array(
  'user1' => array(
    'uid' => 'user1',
    'REMOTE_USER' => 'user2@example.com',
    'eppn' => 'user1@example.com',
    'givenName' => 'Alice',
    'surname' => 'Testuser'
  ),
  'user2' => array(
    'uid' => 'user2',
    'REMOTE_USER' => 'user2@example.com',
    'eppn' => 'user2@example.com',
    'givenName' => 'Bob',
    'surname' => 'Fakeuser'
  )
);
```
### Selecting mock users at runtime
Once the server permits the use of mock users, you must request them through the
query string or an environment variable:

```php
// Via the query string
// Does not persist across requests...
http://example.com/your_shib_script.php?UMNSHIB_MOCK_USER=user1

// Via an environment variable
setenv('UMNSHIB_MOCK_USER', 'user1');
// Or via Apache mod_rewrite as above
```

## Testing
Tests are executed with PHPUnit.  There are _two_ test configurations, owing to
a dependency on environment variables for mock users.

### Primary testing
For basic functionality, `phpunit.xml.dist` has full test coverage. Executing
`phpunit` in the project directory will run the main tests.

### Testing mock users
Since enabling and loading mock users depends on environment variables, a
different PHPUnit configuration is needed to establish the environment at the
beginning of execution.

To run the tests related to probing and loading mock users, do

    phpunit -c phpunit-mockenv.xml


