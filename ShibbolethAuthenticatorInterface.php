<?php

namespace UMNShib;

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
  public function getAttributeNames();
  public function getAttributeValues();
  public function getAttributes();
}
