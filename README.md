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

## Basic Object-oriented or Procedural Usage
Like many modern PHP libraries aiming to provide backward compatibility and ease
of integration into almost any PHP application, this one provides API access
either via a fully object-oriented interface, or via a slightly limited
procedural interface.

Internally, the procedural interface merely wraps the object-oriented one, and
must discard some functionality where it is unable to maintain state.

    use \UMNShib\Basic;

    // Example Object-Oriented instantiation and redirect to login:
    $umnshib = new BasicAuthenticator();
    if (!$umnshib->hasSession()) {
      $umnshib->redirectToLogin($loginOptions);
    }

    // Comparable example using the procedural interface
    if (!umnshib_hasSession()) {
      umnshib_redirectToLogin();
    }

The examples in the previous section demonstrate usage when you may have some custom logic to perform. It
is also possible to make a single call to either retrieve all known attributes
as an array or redirect to a login session:

    use \UMNShib\Basic;

    // Object-oriented style
    $umnshib = new BasicAuthenticator();
    $attributes = $umnshib->getAttributesOrRedirectToLogin();

    // Procedural style
    $attributes = umnshib_getAttributesOrRedirectToLogin();

## Configuration
### Shibboleth.sso handler URL
Most commonly (by default), the Shibboleth SP handler URL is located at
`/Shibboleth.sso` and this library expects to find it there unless otherwise
instructed.

    $umnshib->setHandlerURL('/some/other/path/Shibboleth.sso');

### Shibboleth environment or HTTP headers
If your server is configured to with `ShibUseHeaders on`, you will need to set
it up accordingly via `setAttributeAccessMethod()`. By default it will retrieve
attributes from the web server environment rather than HTTP headers.

    // Object-oriented setup
    $umnshib->setAttributeAccessMethod(\UMNShib\Basic\BasicAuthenticator::UMN_ATTRS_FROM_HEADERS);

When using the procedural interface, functions requiring access to Shibboleth
attributes include a `$useHeaders` boolean parameter, which defaults to `false`.

    // Procedural example retrieving attributes from HTTP headers,
    // pass true as the $useHeaders parameter0
    $uid = umnshib_getAttributeValue('uid', true);

### Login / Logout Options
Several options are available to facilitate features like passive
authentication, 2-factor (MKey) logins, return URLs, forced authentication, or
alternate entity ID.

Methods like `buildLoginURL(), buildLogoutURL(), redirectToLogin(),
redirectToLogout(), getAttributesOrRedirectToLogin()` accept an array paramter
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

    $url = buildLoginURL(array('forceAuthn' => true, 'mkey' => true));

Redirect through the login passively (no login screen) and specify the return
URL:

    redirectToLogin(array(
      'passive' => true,
      'target' => 'https://example.com/passive/login/endpoint'
    ));

Login using the test IdP:

    $url = buildLoginURL(array('IdPEntityID' => BasicAuthenticator::UMN_TEST_IDP_ENTITY_ID));

#### Logout Options
- `return` Return URL
- `logoutFromIdP` Complete a logout from the IdP
- `IdPLogoutURL` Alternate logout URL for IdP

##### Examples
Logout from the IdP, and specify the return URL:

    buildLogoutURL(array(
      'logoutFromIdP' => true,
      'return' => 'https://example.com/logout/endpoint'
    ));

#### Passing options to the constructor on instantiation
Login options may also be passed to the constructor:

    // Options in the constructor
    $umnshib = new BasicAuthenticator(
      // First param is array of login options
      array('forceAuthn' => true, 'target' => 'https://example.com/login/target'),
      // Second param is array of logout options
      array('logoutFromIdP' => true)
    );
    // And they are applied when building URLs...
    $url = $umnshib->buildLoginURL();

