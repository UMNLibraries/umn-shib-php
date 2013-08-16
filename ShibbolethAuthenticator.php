<?php

namespace UMNShib;

class ShibbolethAuthenticator
{
  const UMN_IDP_ENTITY_ID = 'https://idp3.shib.umn.edu/idp/shibboleth';
  const UMN_TEST_IDP_ENTITY_ID = 'https://idp-test.shib.umn.edu/idp/shibboleth';
  const UMN_SPOOF_IDP_ENTITY_ID = 'https://idp-spoof-test.shib.umn.edu/idp/shibboleth';\

  const UMN_IDP_LOGOUT_URL = 'https://idp2.shib.umn.edu/idp/LogoutUMN';
  const UMN_TEST_IDP_LOGOUT_URL = 'https://idp-test.shib.umn.edu/idp/LogoutUMN';
  const UMN_SPOOF_IDP_LOGOUT_URL = 'https://idp-spoof-test.shib.umn.edu/idp/LogoutUMN';

  const UMN_MKEY_AUTHN_CONTEXT = 'https://www.umn.edu/shibboleth/classes/authncontext/mkey';

  const UMN_ATTRS_FROM_ENV = 'from_environment';
  const UMN_ATTRS_FROM_HEADERS = 'from_headers';

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
    'umndid'
  );

  private $maxAge = 10800;
  
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
    array_merge($this->loginOptions, $options)

    $loginBase = $this->getBaseURL();
    $loginTarget = !empty($options['target']) ? urlencode($options['target']) : urlencode($loginBase . $_SERVER['REQUEST_URI']);

    $loginURL = $loginBase . $this->handlerURL . "?$loginTarget";

    if (isset($options['passive']) && $options['passive'] == true) {
      $loginURL .= "&isPassive=true";
    }
    if (isset($options['forceAuthn']) && $options['forceAuthn'] == true) {
      $loginURL .= "&forceAuthn=true";
    }
    if (isset($options['mkey']) && $options['mkey'] == true) {
      $loginURL .= "&authenContextClassRef=" . urlencode(UMN_MKEY_AUTHN_CONTEXT);
    }
    if (isset($options['authenContextClassRef']) && !empty($options['authenContextClassRef'])) {
      $loginURL .= "&authenContextClassRef=" . urlencode($options['authenContextClassRef']);
    }

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
    array_merge($this->logoutOptions, $options)

    $logoutBase = $this->getBaseURL();

    $logoutReturn = '';
    if ($options['logoutFromIdP']) {
      $logoutReturn = self::UMN_IDP_LOGOUT_URL;

      if (!empty($options['return'])) {
        $logoutReturn .= "?return={$options['return']}"
      }

      // The whole return URL is encoded, including the secondary ?return=
      $logoutReturn = '?return=' . urlencode($logoutReturn);
    }

    $logoutURL = $logoutBase . $this->handlerURL . $logoutReturn;
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
    if ($this->getAttributeAccessMethod() == UMN_ATTRS_FROM_ENV) {
      return $_SERVER['Shib-Identity-Provider'];
    }
    else if ($this->getAttributeAccessMethod() == UMN_ATTRS_FROM_HEADERS) {
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

    if ($this->getAttributeAccessMethod() == UMN_ATTRS_FROM_ENV) {
      return in_array($this->getIdPEntityId, $idps);
    }
    if ($this->getAttributeAccessMethod() == UMN_ATTRS_FROM_HEADERS) {
      return in_array($this->getIdPEntityId, $idps);
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
  public function hasSessionTimedOut($maxAge = 10800)
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

  public function loggedInSince() {
    if ($this->getAttributeAccessMethod() == UMN_ATTRS_FROM_ENV) {
      $auth_instant = !empty($_SERVER['Shib-Authentication-Instant']) ? $_SERVER['Shib-Authentication-Instant'] : null;
    }
    else if ($this->getAttributeAccessMethod() == UMN_ATTRS_FROM_HEADERS) {
      $auth_instant = !empty($_SERVER['HTTP_SHIB_AUTHENTICATION_INSTANT']) ? $_SERVER['HTTP_SHIB_AUTHENTICATION_INSTANT'] : null;
    }
    // No authentication instant, no session, return true
    else $auth_instant = null;

    return $auth_instant;
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
    if ($this->hasSession) {
      if ($this->getAttributeAccessMethod() == UMN_ATTRS_FROM_ENV) {
        return $_SERVER['Shib-AuthnContext-Class'] == UMN_MKEY_AUTHN_CONTEXT;
      }
      else {
        return $_SERVER['HTTP_SHIB_AUTHNCONTEXT_CLASS'] == UMN_MKEY_AUTHN_CONTEXT;
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
  private function getServerType()
  {
    if (stripos($_SERVER['SERVER_SOFTWARE'], 'apache') !== false) {
      return 'apache';
    }
    else if (stripos($_SERVER['SERVER_SOFTWARE'], 'iis') !== false {
      return 'iis';
    }
    else return null;
  }
  private function getBaseURL() {
    return 'https://' . $_SERVER['HTTP_HOST'] . $this->handlerURL;
  }

  // Set the path of the handlerURL (default /Shibboleth.sso)
  private function setHandlerURL($handlerURL)
  {
    $this->handlerURL = !empty($handlerURL) ? $handlerURL : "/Shibboleth.sso";
  }

}
?>
