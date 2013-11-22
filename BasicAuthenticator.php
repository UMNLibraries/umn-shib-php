<?php

namespace UMNShib\Basic;

require_once('BasicAuthenticatorInterface.php');
require_once('umn_shib_functions.php');

/**
 * BasicAuthenticator API implementation for UMN Shibboleth
 * 
 * @uses BasicAuthenticatorInterface
 * @package UMNShib\BasicAuthenticator
 * @copyright [Copyright]
 * @author Michael Berkowski <mjb@umn.edu> 
 * @license [License]
 */
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

  /**
   * From what source are attributes read (HTTP_SHIB_ headers or environment variables)?
   * Values should be self::UMN_ATTRS_FROM_ENV, self::UMN_ATTRS_FROM_HEADERS
   * 
   * @var mixed
   * @access protected
   */
  protected $attributeSource = self::UMN_ATTRS_FROM_ENV;
  /**
   * URI path of the Shibboleth SessionInitiator
   * Default '/Shibboleth.sso'
   * 
   * @var string
   * @access protected
   */
  protected $handlerURL = '/Shibboleth.sso';
  /**
   * Default login options
   * 
   * @var array
   * @access protected
   */
  protected $loginOptions = array();
  /**
   * Default logout options
   * 
   * @var array
   * @access protected
   */
  protected $logoutOptions = array(
    'return' => null,
    'logoutFromIdP' => true,
    'IdPLogoutURL' => self::UMN_IDP_ENTITY_ID
  );
  /**
   * Default attributes supplied by UMN IdP
   * 
   * @var array
   * @access protected
   */
  protected $attributes = array(
    'uid',
    'eppn',
    'isGuest',
    'umnDID'
  );
  
  public function __construct($loginOptions = array(), $logoutOptions = array())
  {
    // Login/Logout options may be supplied in the constructor
    if (is_array($loginOptions)) {
      $this->loginOptions = array_merge($this->loginOptions, $loginOptions);
    }
    if (is_array($logoutOptions)) {
      $this->logoutOptions = array_merge($this->logoutOptions, $logoutOptions);
    }
  }
  /**
   * Construct a Session Initiator URL based on options
   * 
   * @param array $options Associative array of options will be merged with defaults or options supplied in the constructor
   * @access public
   * @return string
   */
  public function buildLoginURL(array $options = array())
  {
    $loginBase = $this->getBaseURL();
    // Input options merge/overwrite default options
    $options = array_merge($this->loginOptions, $options);

    $params = array();
    // Parse explicit and implicit options, build the query string
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

    $loginURL = $loginBase . $this->handlerURL . '/Login';
    if (!empty($query)) {
      $loginURL .= "?$query";
    }
    return $loginURL;
  }
  /**
   * Construct a logout URL based on options
   * 
   * @param array $options Associative array of options will be merged with defaults or options supplied in the constructor
   * @access public
   * @return string
   */
  public function buildLogoutURL(array $options = array())
  {
    $logoutBase = $this->getBaseURL();
    // Input options merge/overwrite default logout options
    $options = array_merge($this->logoutOptions, $options);

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

    $query = http_build_query($params);
    $logoutURL = $logoutBase . $this->handlerURL . '/Logout';
    if (!empty($query)) {
      $logoutURL .= "?$query";
    }
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
    $name = $this->normalizeAttributeName('Shib-Identity-Provider');
    return !empty($_SERVER[$name]) ? $_SERVER[$name] : null;
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
   * @param integer $maxAge Maximum session lifetime in seconds, default UMN_SESSION_MAX_AGE
   * @access public
   * @return bool
   */
  public function hasSessionTimedOut($maxAge = self::UMN_SESSION_MAX_AGE)
  { 
    // If no session can be found, just return
    if (!$this->hasSession()) {
      return true;
    }

    $auth_instant_ts = $this->loggedInSince();
    if ($auth_instant_ts) {
      // Timestamp of auth plus maxAge is earlier than current time
      return $auth_instant_ts + $maxAge < time();
    }
    else return false;
  }
  /**
   * Returns the Shib-Authentication-Instant as a Unix timestamp
   * 
   * @access public
   * @return integer
   */
  public function loggedInSince() {
    $auth_instant = $this->getAttributeValue('Shib-Authentication-Instant');
    return strtotime($auth_instant);
  }
  /**
   * Returns the current session's attributes or forces a login redirect if no session is present
   * 
   * @param array $options Array of login options, see buildLoginURL()
   * @param array $requestedAttributes 
   * @param integer $maxAge Maximum session lifetime in seconds, default UMN_SESSION_MAX_AGE
   * @access public
   * @return array
   */
  public function getAttributesOrRequestLogin(array $options = array(), array $requestedAttributes = array(), $maxAge = self::UMN_SESSION_MAX_AGE)
  {
    if ($this->hasSessionTimedOut($maxAge)) {
      $this->redirectToLogin($options);
    }
    else {
      // Login is good, return attributes passing in requested set or default if not specified
      return $this->getAttributes($requestedAttributes);
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
      $auth_method = $this->getAttributeValue('Shib-Authentication-Method');
      return $auth_method == self::UMN_MKEY_AUTHN_CONTEXT;
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

    if ($this->getServerType() == self::SERVER_TYPE_IIS) {
      $this->attributeSource = self::UMN_ATTRS_FROM_HEADERS;
    }
    else $this->attributeSource = self::UMN_ATTRS_FROM_HEADERS;
    return $this->attributeSource;
  }
  /**
   * Set the attribute access method, allows us to force the use of HTTP headers even absent 
   * their having been populated by ShibUseHeaders
   * 
   * @param mixed $accessMethod 
   * @access public
   * @return bool
   */
  public function setAttributeAccessMethod($accessMethod)
  {
    if (!in_array($accessMethod, array(self::UMN_ATTRS_FROM_ENV, self::UMN_ATTRS_FROM_HEADERS))) {
      throw new \InvalidArgumentException("Unknown attribute source");
    }
    $this->attributeSource = $accessMethod;
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
  /**
   * getAttributeNames
   * 
   * @param array $requestedAttributes 
   * @access public
   * @return array
   */
  public function getAttributeNames(array $requestedAttributes = array()) {
    return array_merge($this->attributes, $requestedAttributes);
  }
  /**
   * Return an attribute value
   * 
   * @param string $name 
   * @access public
   * @return string
   */
  public function getAttributeValue($name) {
    $value = null;
    $name = $this->normalizeAttributeName($name);
    return !empty($_SERVER[$name]) ? $_SERVER[$name] : null;
  }
  /**
   * Return an array of values from a delimited, multi-value attribute
   * 
   * @param string $name 
   * @param string $delimiter
   * @access public
   * @return array
   */
  public function getAttributeValues($name, $delimiter = ';') {
    $value = null;
    $name = $this->normalizeAttributeName($name);
    if (!empty($_SERVER[$name])) $value = explode($delimiter, $_SERVER[$name]);
    return $value;
  }
  /**
   * getAttributes
   * 
   * @param array $requestedAttributes 
   * @access public
   * @return array
   */
  public function getAttributes(array $requestedAttributes = array()) {
    $attrs = array_flip(array_merge($this->getAttributeNames(), $requestedAttributes));
    foreach ($attrs as $key => $value) {
      $key = $this->normalizeAttributeName($key);
      $attrs[$key] = isset($_SERVER[$key]) ? $_SERVER[$key] : null;
    }
    return $attrs;
  }
  /**
   * Return the currently configured login options
   * 
   * @access public
   * @return array
   */
  public function getLoginOptions()
  {
    return $this->loginOptions;
  }
  /**
   * Return the currently configured logout options
   * 
   * @access public
   * @return array
   */
  public function getLogoutOptions()
  {
    return $this->logoutOptions;
  }
  /**
   * Set the path of the handlerURL (default /Shibboleth.sso) and return it
   * 
   * @param mixed $handlerURL 
   * @access public
   * @return string
   */
  public function setHandlerURL($handlerURL)
  {
    $this->handlerURL = !empty($handlerURL) ? $handlerURL : "/Shibboleth.sso";
    return $this->handlerURL;
  }
  /**
   * Return the current handlerURL fragment  like /Shibboleth.sso
   * 
   * @access public
   * @return string
   */
  public function getHandlerURL()
  {
    return $this->handlerURL;
  }
  /**
   * Handle HTTP redirection
   * 
   * @param string $url
   * @access protected
   * @return void
   */
  protected function redirect($url)
  {
    header("Location: $url");
    exit();
  }
  /**
   * Returns the server type (iis, apache)
   * 
   * @access protected
   * @return string
   */
  protected function getServerType()
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
   * @access protected
   * @return string
   */
  protected function getBaseURL()
  {
    return 'https://' . $_SERVER['HTTP_HOST'];
  }
  /**
   * Return the bare attribute name or HTTP_ header version according to $attributeSource
   * 
   * @param string $name Shibboleth attribute name
   * @access protected
   * @return string
   */
  protected function normalizeAttributeName($name)
  {
    if ($this->getAttributeAccessMethod() == self::UMN_ATTRS_FROM_HEADERS) {
      $name = self::convertToHTTPHeaderName($name);
    }
    return $name;
  }
  /**
   * Return a string representing the HTTP header corresponding to the input $shibProperty
   * This means replacing hyphens with underscores and prepending HTTP_
   * 
   * @param mixed $shibProperty 
   * @access protected
   * @return bool
   */
  protected static function convertToHTTPHeaderName($shibProperty)
  {
    return 'HTTP_' . strtoupper(str_replace('-', '_', $shibProperty));
  }
}
?>
