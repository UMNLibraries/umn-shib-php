<?php

namespace UMNShib\BasicAuthenticator;

/**
 * BasicAuthenticatorInterface
 * 
 * @package UMNShib\BasicAuthenticator
 * @copyright [Copyright]
 * @author Michael Berkowski <mjb@umn.edu> 
 * @license [License]
 */
Interface BasicAuthenticatorInterface
{
  public function buildLoginURL(array $options = array());
  public function buildLogoutURL(array $options = array());
  public function redirectToLogin(array $options = array());
  public function getAttributesOrRequestLogin(array $options);
  public function redirectToLogout(array $options = array());

  public function getIdPEntityId();
  public function hasSession();
  public function hasSessionTimedOut($maxAge = 10800);
  public function loggedInSince();
  public function loggedInWithMKey();

  public function getAttributeAccessMethod();
  public function getDefaultAttributeNames();
  public function getAttributeNames($requestedAttributes);
  public function getAttributeValue($name);
  public function getAttributeValues($name);
  public function getAttributes($requestedAttributes);
}
