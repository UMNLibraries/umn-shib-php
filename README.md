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

    // Example Object-Oriented instantiation and redirect to login:
    $umnshib = new \UMNShib\Basic\BasicAuthenticator();
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

    // Object-oriented style
    $umnshib = new \UMNShib\Basic\BasicAuthenticator();
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

