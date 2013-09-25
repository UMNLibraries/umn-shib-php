<?php
namespace UMNShib\BasicAuthenticator;

require_once('BasicAuthenticator.php');

function umnshib_buildLoginURL(array $options = array())
{
  $shib = new BasicAuthenticator();
  return $shib->buildLoginURL($options);
}
function umnshib_buildLogoutURL(array $options = array())
{
  $shib = new BasicAuthenticator();
  return $shib->buildLogoutURL($options);
}
function umnshib_redirectToLogin(array $options = array())
{
  $shib = new BasicAuthenticator();
  $shib->redirectToLogin($options);
}
function umnshib_redirectToLogout(array $options = array())
{
  $shib = new BasicAuthenticator();
  $shib->redirectToLogout($options);
}
function umnshib_hasSession($use_headers = false)
{
  $shib = _umnshib_get_object($use_headers);
  return $shib->hasSession();
}
function umnshib_hasSessionTimedOut($maxAge = BasicAuthenticator::UMN_SESSION_MAX_AGE, $use_headers = false)
{
  $shib = _umnshib_get_object($use_headers);
  return $shib->hasSessionTimedOut($maxAge);
}
function umnshib_loggedInSince($use_headers = false)
{
  $shib = _umnshib_get_object($use_headers);
  return $shib->loggedInSince();
}
function umnshib_getIdPEntityId($use_headers = false)
{
  $shib = _umnshib_get_object($use_headers);
  return $shib->getIdPEntityId();
}
function umnshib_loggedInWithMKey($use_headers = false)
{
  $shib = _umnshib_get_object($use_headers);
  return $shib->loggedInWithMKey();
}
function umnshib_getAttributesOrRequestLogin(array $options = array(), $use_headers = false)
{
  $shib = _umnshib_get_object($use_headers);
  return $shib->getAttributesOrRequestLogin($options);
}
function umnshib_getAttributeValue($name, $use_headers = false)
{
  $shib = _umnshib_get_object($use_headers);
  return $shib->getAttributeValue($name);
}
function umnshib_getAttributeValues($name, $use_headers = false)
{
  $shib = _umnshib_get_object($use_headers);
  return $shib->getAttributeValues($name);
}

function _umnshib_get_object($use_headers = false)
{
  $shib = new BasicAuthenticator();
  if ($use_headers) {
    $shib->setAttributeAccessMethod(BasicAuthenticator::UMN_ATTRS_FROM_HEADERS);
  }
  return $shib;
}
?>
