<?php

namespace UMNShib;

class BasicAuthenticator implements BasicAuthenticatorInterface
{
  // API Constants
  const UMN_IDP_ENTITY_ID = 'https://idp2.shib.umn.edu/idp/shibboleth';
  const UMN_TEST_IDP_ENTITY_ID = 'https://idp-test.shib.umn.edu/idp/shibboleth';
  const UMN_SPOOF_IDP_ENTITY_ID = 'https://idp-spoof-test.shib.umn.edu/idp/shibboleth';

  const UMN_IDP_LOGOUT_URL = 'https://idp2.shib.umn.edu/idp/LogoutUMN';
  const UMN_TEST_IDP_LOGOUT_URL = 'https://idp-test.shib.umn.edu/idp/LogoutUMN';
  const UMN_SPOOF_IDP_LOGOUT_URL = 'https://idp-spoof-test.shib.umn.edu/idp/LogoutUMN';

  const UMN_MKEY_AUTHN_CONTEXT = 'https://www.umn.edu/shibboleth/classes/authncontext/mkey';

  const UMN_ATTRS_FROM_ENV = 'from_environment';
  const UMN_ATTRS_FROM_HEADERS = 'from_headers';
  
  // Extended constants
  const UMN_SESSION_MAX_AGE = 10800;
  const SERVER_TYPE_IIS = 'iis';
  const SERVER_TYPE_APACHE = 'apache';
  const SERVER_TYPE_OTHER = 'other';

  private $attributeSource = self::UMN_ATTRS_FROM_ENV;

  private $handlerURL = '/Shibboleth.sso';

  private $loginOptions = array();

  private $logoutOptions = array(
    'return' => null,
    'logoutFromIdP' => true,
    'IdPLogoutURL' => self::UMN_IDP_ENTITY_ID
  );

  private $attributes = array(
    'uid',
    'eppn',
    'isGuest',
    'umnDID'
  );

  
  public function __construct()
  {

  }

  /**
   * Construct a Session Initiator URL based on options
   * 
   * @param array $options Associative array of options
   * @access public
   * @return string
   */
  public function buildLoginURL(array $options = array())
  {
    array_merge($this->loginOptions, $options);

    $loginBase = $this->getBaseURL();

    $params = array();

    // Default to the current URI if no target was supplied
    $params['target'] = !empty($options['target']) ? $options['target'] : $loginBase . $_SERVER['REQUEST_URI'];

    if (isset($options['entityID'])) {
      $params['entityID'] = $options['entityID'];
    }
    if (isset($options['passive']) && $options['passive'] == true) {
      $params['isPassive'] = 'true';
    }
    if (isset($options['forceAuthn']) && $options['forceAuthn'] == true) {
      $params['forceAuthn'] = 'true';
    }
    if (isset($options['mkey']) && $options['mkey'] == true) {
      $params['authnContextClassRef'] = self::UMN_MKEY_AUTHN_CONTEXT;
    }
    if (isset($options['authnContextClassRef']) && !empty($options['authnContextClassRef'])) {
      $params['authnContextClassRef'] = $options['authnContextClassRef'];
    }
    $query = http_build_query($params);

    $loginURL = $loginBase . $this->handlerURL . "/Login?$query";
    return $loginURL;
  }
  
  /**
   * Construct a logout URL based on options
   * 
   * @param array $options
   * @access public
   * @return string
   */
  public function buildLogoutURL(array $options = array())
  {
    array_merge($this->logoutOptions, $options);

    $logoutBase = $this->getBaseURL();

    $params = array();
    if ($options['logoutFromIdP']) {
      $logoutReturn = self::UMN_IDP_LOGOUT_URL;

      // Append the urlencoded final return
      if (!empty($options['return'])) {
        $logoutReturn .= "?return={$options['return']}";
      }

      // The whole return URL is encoded, including the secondary ?return=
      $params['return'] = $logoutReturn;
    }

    $logoutURL = $logoutBase . $this->handlerURL . '/Logout?' . http_build_query($params);
    return $logoutURL;
  }

  /**
   * Redirect to a login URL, calls buildLoginURL()
   * 
   * @param array $options 
   * @access public
   * @return void
   */
  public function redirectToLogin(array $options = array())
  {
    $this->redirect($this->buildLoginURL($options));
  }

  /**
   * Redirect to a logout URL, calls buildLogoutURL()
   * 
   * @param array $options 
   * @access public
   * @return void
   */
  public function redirectToLogout(array $options = array())
  {
    $this->redirect($this->buildLogoutURL($options));
  }

  /**
   * Returns the Shib-Identity-Provider if non-empty
   * 
   * @access public
   * @return string
   */
  public function getIdPEntityId() {
    if ($this->getAttributeAccessMethod() == self::UMN_ATTRS_FROM_ENV) {
      return $_SERVER['Shib-Identity-Provider'];
    }
    else if ($this->getAttributeAccessMethod() == self::UMN_ATTRS_FROM_HEADERS) {
      return $_SERVER['HTTP_SHIB_IDENTITY_PROVIDER'];
    }
    return null;
  }
  /**
   * Returns true if the Shib-Identity-Provider is non-empty and one of our 3 expected values
   * 
   * @access public
   * @return bool
   */
  public function hasSession() {
    $idps = array(self::UMN_IDP_ENTITY_ID, self::UMN_TEST_IDP_ENTITY_ID, self::UMN_SPOOF_IDP_ENTITY_ID);

    if ($this->getAttributeAccessMethod() == self::UMN_ATTRS_FROM_ENV) {
      return in_array($this->getIdPEntityId(), $idps);
    }
    if ($this->getAttributeAccessMethod() == self::UMN_ATTRS_FROM_HEADERS) {
      return in_array($this->getIdPEntityId(), $idps);
    }
    return false;
  }
  /**
   * Does a valid session exist with the SP?
   * Returns true if the elapsed time since authentication is greater than maxAge
   * 
   * @param integer $maxAge Maximum session lifetime in minutes, default 180 (3 hours)
   * @access public
   * @return bool
   */
  public function hasSessionTimedOut($maxAge = self::UMN_SESSION_MAX_AGE)
  { 
    // If no session can be found, just return
    if (!$this->hasSession()) {
      return true;
    }

    $auth_instant = $this->loggedInSince();
    if ($auth_instant) {
      $auth_instant_ts = strtotime($auth_instant);
      // Timestamp of auth plus maxAge is later than current time
      return $auth_instant_ts + $maxAge < time();
    }
    else return true;
  }
  /**
   * Returns the Shib-Authentication-Instant as a Unix timestamp
   * 
   * @access public
   * @return integer
   */
  public function loggedInSince() {
    if ($this->getAttributeAccessMethod() == self::UMN_ATTRS_FROM_ENV) {
      $auth_instant = !empty($_SERVER['Shib-Authentication-Instant']) ? $_SERVER['Shib-Authentication-Instant'] : null;
    }
    else if ($this->getAttributeAccessMethod() == self::UMN_ATTRS_FROM_HEADERS) {
      $auth_instant = !empty($_SERVER['HTTP_SHIB_AUTHENTICATION_INSTANT']) ? $_SERVER['HTTP_SHIB_AUTHENTICATION_INSTANT'] : null;
    }
    // No authentication instant, no session, return true
    else $auth_instant = null;

    return strtotime($auth_instant);
  }
  /**
   * Returns the current session's attributes or forces a login redirect if no session is present
   * 
   * @param array $options Array of login options, see buildLoginURL()
   * @access public
   * @return array
   */
  public function getAttributesOrRequestLogin(array $options)
  {
    if ($this->hasSessionTimedOut($this->maxAge)) {
      $this->redirectToLogin($options);
    }
    else {
      return $this->getAttributes();
    }
  }
  /**
   * Returns true if the user was logged in with an MKey
   * 
   * @access public
   * @return bool
   */
  public function loggedInWithMKey() {
    if ($this->hasSession()) {
      if ($this->getAttributeAccessMethod() == self::UMN_ATTRS_FROM_ENV) {
        return $_SERVER['Shib-AuthnContext-Class'] == self::UMN_MKEY_AUTHN_CONTEXT;
      }
      else {
        return $_SERVER['HTTP_SHIB_AUTHNCONTEXT_CLASS'] == self::UMN_MKEY_AUTHN_CONTEXT;
      }
    }
    return false;
  }
  /**
   * Return the attribute access method (ENV, or HTTP headers)
   * 
   * @access public
   * @return bool
   */
  public function getAttributeAccessMethod()
  {
    if (!empty($this->attributeSource)) {
      return $this->attributeSource;
    }

    if ($this->getServerType() == 'iis') {
      $this->attributeSource = 'iis';
    }
    else $this->attributeSource = 'apache';
    return $this->attributeSource;
  }
  /**
   * Return the array of default attribute names
   * 
   * @access public
   * @return array
   */
  public function getDefaultAttributeNames()
  {
    return $this->attributes;
  }
  public function getAttributeNames() {}
  public function getAttributeValues() {}
  public function getAttributes() {}

  /**
   * Handle HTTP redirection
   * 
   * @param string $url
   * @access private
   * @return void
   */
  private function redirect($url) {
    header("Location $url");
    exit();
  }
  /**
   * Returns the server type (iis, apache)
   * 
   * @access private
   * @return string
   */
  private function getServerType()
  {
    if (stripos($_SERVER['SERVER_SOFTWARE'], self::SERVER_TYPE_APACHE) !== false) {
      return self::SERVER_TYPE_APACHE;
    }
    else if (stripos($_SERVER['SERVER_SOFTWARE'], self::SERVER_TYPE_IIS) !== false) {
      return self::SERVER_TYPE_IIS;
    }
    else return self::SERVER_TYPE_OTHER;
  }
  /**
   * Return the base URL, protocol and hostname, up to but not including the REQUEST_URI
   * 
   * @access private
   * @return string
   */
  private function getBaseURL() {
    return 'https://' . $_SERVER['HTTP_HOST'];
  }

  /**
   * Set the path of the handlerURL (default /Shibboleth.sso) and return it
   * 
   * @param mixed $handlerURL 
   * @access private
   * @return string
   */
  private function setHandlerURL($handlerURL)
  {
    $this->handlerURL = !empty($handlerURL) ? $handlerURL : "/Shibboleth.sso";
    return $this->handlerURL;
  }
}
?>
