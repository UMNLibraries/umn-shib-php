<?php

use UMNShib\Basic\BasicAuthenticator;

/**
 * Procedural interface to BasicAuthenticator API implementation for UMN Shibboleth
 * Allows single function calls to perform basic Shibboleth actions like URL generation
 * redirection to login/logout, etc.  These function calls maintain no state!
 * Every call is an independent, one-off action instantiating its own new BasicAuthenticator
 * object and discarding it when it is completed.
 *
 * Example to enforce a passive login with one function call:
 *   $user_attributes = umnshib_getAttributesOrRequestLogin(array('isPassive' => true));
 * 
 * @uses BasicAuthenticator
 * @package UMNShib\BasicAuthenticator
 * @copyright [Copyright]
 * @author Michael Berkowski <mjb@umn.edu> 
 * @license [License]
 */

require_once('BasicAuthenticator.php');

/**
 * Construct a Session Initiator URL based on options
 * 
 * @param array $options Associative array of options will be merged with defaults or options supplied in the constructor
 * @return string
 */
function umnshib_buildLoginURL(array $options = array())
{
  $shib = new BasicAuthenticator();
  return $shib->buildLoginURL($options);
}
/**
 * Construct a logout URL based on options
 * 
 * @param array $options Associative array of options will be merged with defaults or options supplied in the constructor
 * @return string
 */
function umnshib_buildLogoutURL(array $options = array())
{
  $shib = new BasicAuthenticator();
  return $shib->buildLogoutURL($options);
}
/**
 * Redirect to a login URL
 * 
 * @param array $options 
 * @return void
 */
function umnshib_redirectToLogin(array $options = array())
{
  $shib = new BasicAuthenticator();
  $shib->redirectToLogin($options);
}
/**
 * Redirect to a logout URL
 * 
 * @param array $options 
 * @return void
 */
function umnshib_redirectToLogout(array $options = array())
{
  $shib = new BasicAuthenticator();
  $shib->redirectToLogout($options);
}
/**
 * Returns true if the Shib-Identity-Provider is non-empty and one of our 3 expected values
 * 
 * @param bool $use_headers Retrieve attributes from HTTP_ headers, default false
 * @param string $prefix Attribute prefix
 * @return bool
 */
function umnshib_hasSession($use_headers = false, $prefix = '')
{
  $shib = _umnshib_get_object($use_headers, $prefix);
  return $shib->hasSession();
}
/**
 * Does a valid session exist with the SP?
 * Returns true if the elapsed time since authentication is greater than maxAge
 * 
 * @param integer $maxAge Maximum session lifetime in minutes, default 180 (3 hours)
 * @param bool $use_headers Retrieve attributes from HTTP_ headers, default false
 * @param string $prefix Attribute prefix
 * @return bool
 */
function umnshib_hasSessionTimedOut($maxAge = BasicAuthenticator::UMN_SESSION_MAX_AGE, $use_headers = false, $prefix = '')
{
  $shib = _umnshib_get_object($use_headers, $prefix);
  return $shib->hasSessionTimedOut($maxAge);
}
/**
 * Returns the Shib-Authentication-Instant as a Unix timestamp
 * 
 * @param bool $use_headers Retrieve attributes from HTTP_ headers, default false
 * @param string $prefix Attribute prefix
 * @return integer
 */
function umnshib_loggedInSince($use_headers = false, $prefix = '')
{
  $shib = _umnshib_get_object($use_headers, $prefix);
  return $shib->loggedInSince();
}
function umnshib_getAttributesOrRequestLogin(array $options = array(), $use_headers = false, $prefix = '')
{
  $shib = _umnshib_get_object($use_headers, $prefix);
  return $shib->getAttributesOrRequestLogin($options);
}
/**
 * Returns the Shib-Identity-Provider if non-empty
 * 
 * @param bool $use_headers Retrieve attributes from HTTP_ headers, default false
 * @param string $prefix Attribute prefix
 * @return string
 */
function umnshib_getIdPEntityId($use_headers = false, $prefix = '')
{
  $shib = _umnshib_get_object($use_headers, $prefix);
  return $shib->getIdPEntityId();
}
/**
 * Returns true if the user was logged in with an MKey
 * 
 * @param bool $use_headers Retrieve attributes from HTTP_ headers, default false
 * @param string $prefix Attribute prefix
 * @return bool
 */
function umnshib_loggedInWithMKey($use_headers = false, $prefix = '')
{
  $shib = _umnshib_get_object($use_headers, $prefix);
  return $shib->loggedInWithMKey();
}
/**
 * Return the array of default attribute names
 * 
 * @return array
 */
function umnshib_getDefaultAttributeNames()
{
  $shib = new BasicAuthenticator();
  return $shib->getDefaultAttributeNames();
}
/**
 * getAttributeNames
 * 
 * @param array $requestedAttributes 
 * @return array
 */
function umnshib_getAttributeNames(array $requestedAttributes = array())
{
  $shib = new BasicAuthenticator();
  return $shib->getAttributeNames($requestedAttributes);
}
/**
 * Return an attribute value
 * 
 * @param string $name 
 * @param bool $use_headers Retrieve attributes from HTTP_ headers, default false
 * @param string $prefix Attribute prefix
 * @return string
 */
function umnshib_getAttributeValue($name, $use_headers = false, $prefix = '')
{
  $shib = _umnshib_get_object($use_headers, $prefix);
  return $shib->getAttributeValue($name);
}
/**
 * Return an array of values from a delimited, multi-value attribute
 * 
 * @param string $name 
 * @param string $delimiter
 * @param bool $use_headers Retrieve attributes from HTTP_ headers, default false
 * @param string $prefix Attribute prefix
 * @return array
 */
function umnshib_getAttributeValues($name, $delimiter = ';', $use_headers = false, $prefix = '')
{
  $shib = _umnshib_get_object($use_headers, $prefix);
  return $shib->getAttributeValues($name);
}

/**
 * Return a BasicAuthenticator object and set its attribute access method
 *
 * @param bool $use_headers Retrive attributes from HTTP_ headers, default false
 * @param string $prefix Attribute prefix
 * @return BasicAuthenticator
 */
function _umnshib_get_object($use_headers = false, $prefix = '')
{
  $shib = new BasicAuthenticator();
  if ($use_headers) {
    $shib->setAttributeAccessMethod(BasicAuthenticator::UMN_ATTRS_FROM_HEADERS);
  }
  $shib->setAttributePrefix($prefix);
  return $shib;
}
?>
