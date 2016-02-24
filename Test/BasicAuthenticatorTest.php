<?php
namespace UMNShib\Basic\Test;

use UMNShib\Basic\BasicAuthenticator;

class BasicAuthenticatorTest extends \PHPUnit_Framework_TestCase
{
  private $http_host = 'example.com';
  private $default_handler_url = '/Shibboleth.sso';
  private $alt_handler_url = '/shibboleth/Shibboleth.sso';
  private $request_uri = '/test/index.html?param=123';
  private $alt_request_uri ='/altdir/test/';
  private $alt_base_url = 'https://example.edu';

  public function setUp()
  {
    // Initialize _SERVER superglobal since this is a CLI run
    $shib_server = array(
      'HTTP_HOST' => $this->http_host,
      'REQUEST_URI' => $this->request_uri,
      'Shib-Identity-Provider' => BasicAuthenticator::UMN_IDP_ENTITY_ID,
      'HTTP_SHIB_IDENTITY_PROVIDER' => BasicAuthenticator::UMN_TEST_IDP_ENTITY_ID, // Different for test distinction
      'Shib-Authentication-Instant' => date('c', time() - 1800),
      'HTTP_SHIB_AUTHENTICATION_INSTANT' => date('c', time() - 3600), // Earlier login in the header (for test distinction)
      'Shib-AuthnContext-Class' => BasicAuthenticator::UMN_MKEY_AUTHN_CONTEXT,
      'Shib-Authentication-Method' => BasicAuthenticator::UMN_MKEY_AUTHN_CONTEXT,
      'REMOTE_USER' => 'user@example.com',
      'eppn' => 'user@example.com',
      'HTTP_EPPN' => 'user@example.com',
      'uid' => 'user',
      'HTTP_UID' => 'user',
      'multiAttribute' => 'one;two;three',
      'HTTP_MULTIATTRIBUTE' => 'one;two;three'
    );
    $GLOBALS['_SERVER'] = array_merge($GLOBALS['_SERVER'], $shib_server);

    ini_set('arg_separator.output', '&');
  }
  public function tearDown()
  {
    // Get rid of shib-related keys we've set by sting match
    foreach (array_keys($_SERVER) as $key) {
      if (strpos($key, 'Shib') !== false || strpos($key, 'HTTP_SHIB') !== false) {
        unset($_SERVER[$key]);
      }
    }
    // And other keys we set
    $keys = array(
      'HTTP_HOST',
      'REQUEST_URI',
      'REMOTE_USER',
      'eppn',
      'HTTP_EPPN',
      'uid',
      'HTTP_UID',
      'multiAttribute',
      'HTTP_MULTIATTRIBUTE'
    );
    foreach ($keys as $key) {
      if (isset($_SERVER[$key])) unset($_SERVER[$key]);
    }
  }
  public function testConstructorLoginOptions()
  {
    $login_options = array(
      'isPassive' => true,
      'mkey' => true
    );

    $shib = new BasicAuthenticator($login_options);
    // Default login options are empty, so these should be the only ones set
    $this->assertEquals($login_options, $shib->getLoginOptions());
  }
  public function testConstructorLogoutOptions()
  {
    // Input overwrites some defaults and adds an option
    $input_logout_options = array(
      'return' => 'http://www.example.com',
      'logoutFromIdP' => false,
      'otherOption' => true
    );
    // Result should have overwritten defaults plus existing defaults, and added option
    $expected_logout_options = array(
      'return' => 'http://www.example.com',
      'logoutFromIdP' => false,
      'IdPLogoutURL' => BasicAuthenticator::UMN_IDP_ENTITY_ID,
      'otherOption' => true
    );
    $shib = new BasicAuthenticator(null, $input_logout_options);
    $this->assertEquals($expected_logout_options, $shib->getLogoutOptions());
  }
  public function testLoginURL()
  {
    $shib = new BasicAuthenticator();

    // Build a most basic login URL
    $url = $shib->buildLoginURL();

    // It should begin with https:// followed by http_host followed by default_handler_url
    $expected_base = "https://{$this->http_host}{$this->default_handler_url}/Login";
    $this->assertEquals($expected_base, substr($url, 0, strlen($expected_base)), "The protocol, hostname, and Shibboleth handler should match");

    // It should also contain a urlencoded target= parameter with the full proto,host,request uri
    $expected_qs = "target=" . urlencode("https://{$this->http_host}{$this->request_uri}");
    $this->assertEquals($expected_qs, substr($url, -strlen($expected_qs)), "The generated URL should end with a urlencoded target= URL");

    // Build a login URL with isPassive
    $url = $shib->buildLoginURL(array('passive' => true));
    $expected_qs_passive = "isPassive=true&" . $expected_qs;
    $this->assertEquals($expected_qs_passive, substr($url, -strlen($expected_qs_passive)), "The generated URL should begin with isPassive=true");

    // Mkey option
    $url = $shib->buildLoginURL(array('mkey' => true));
    $mkey_qs = preg_replace('/^' . preg_quote($expected_base, '/') . '\?/', '', $url);
    $expected_mkey = "authnContextClassRef=" . urlencode(BasicAuthenticator::UMN_MKEY_AUTHN_CONTEXT);
    $this->assertEquals($expected_mkey, substr($mkey_qs, 0, strlen($expected_mkey)), "The generated URL should begin with an encoded authnContextClass for MKEY");

    // Multiple options (explicit target and forceAuthn)
    $expected_base_alt = "https://{$this->http_host}{$this->alt_request_uri}";
    $expected_qs_target = "target=" . urlencode($expected_base_alt);
    $expected_qs_force = "forceAuthn=true&";
    $url = $shib->buildLoginURL(array('target' => $expected_base_alt, 'forceAuthn' => true));
    $this->assertTrue(strpos($url, $expected_qs_target) !== false, "The generated URL should contain the encoded explicit target");
    $this->assertTrue(strpos($url, $expected_qs_force) !== false, "The generated URL should contain a forceAuthn=true parameter");
  }

  public function testLogoutURL()
  {
    $shib = new BasicAuthenticator();

    // Build a basic logout URL
    $url = $shib->buildLogoutURL();

    // It should begin with https:// followed by http_host followed by default_handler_url and /Logout
    $expected_base = "https://{$this->http_host}{$this->default_handler_url}/Logout";
    $this->assertEquals($expected_base, substr($url, 0, strlen($expected_base)), "The protocol, hostname, and Shibboleth handler should match");

    // Verify the return= URL since logoutFromIdP is the default
    $expected_qs = "?return=" . urlencode(BasicAuthenticator::UMN_IDP_LOGOUT_URL);
    $this->assertEquals($expected_qs, substr($url, -strlen($expected_qs)), "A default logout URL should contain an encoded return to the IdP logout URL");

    // Build a SP-only logout, contains no query string, should match the original base URL
    $url = $shib->buildLogoutURL(array('logoutFromIdP' => false));
    $this->assertEquals($expected_base, $url, "Without an IdP logout, the generated URL should have no query string");

    // Build SP-only logout with return=
    $return_url = "https://{$this->http_host}{$this->alt_request_uri}";
    $url = $shib->buildLogoutURL(array('logoutFromIdP' => false, 'return' => $return_url));
    $expected_return = "?return=" . urlencode($return_url);
    $this->assertEquals($expected_base . $expected_return, $url, "Without an IdP logout, the generated URL should still include a return URL");

    // Build an IdP logout with an explicit additional return URL
    $return_url = "https://{$this->http_host}{$this->alt_request_uri}";
    $url = $shib->buildLogoutURL(array('logoutFromIdP' => true, 'return' => $return_url));

    $expected_return = "?return=" . urlencode(BasicAuthenticator::UMN_IDP_LOGOUT_URL . "?return={$return_url}");
    $this->assertEquals($expected_return, substr($url, -strlen($expected_return)), "The generated URL should contain an encoded IdP logout with an additional encoded return URL inside it");
  }

  public function testAlternateHandlerURL()
  {
    $shib = new BasicAuthenticator();
    // Set a different handler URL
    $shib->setHandlerURL($this->alt_handler_url);
    $url = $shib->buildLoginURL();

    $this->assertEquals($this->alt_handler_url, $shib->getHandlerURL(), "It should return the explicitly set handlerURL");
    // Verify that a default login URL contains the correct handler path
    $expected_base = "https://{$this->http_host}{$this->alt_handler_url}";
    $this->assertEquals($expected_base, substr($url, 0, strlen($expected_base)), "The protocol, hostname, and explicitly set Shibboleth handler should match");
  }

  public function testAlternateBaseURL()
  {
    $shib = new BasicAuthenticator();
    $shib->setBaseURL($this->alt_base_url);
    $loginurl = $shib->buildLoginURL();
    $logouturl = $shib->buildLogoutURL();

    $this->assertEquals($this->alt_base_url, $shib->getBaseURL(), "The base URL should match the explicitly set URL");

    $expected_login = "{$this->alt_base_url}{$this->default_handler_url}/Login";
    $this->assertEquals($expected_login, substr($loginurl, 0, strlen($expected_login)), "The generated login URL should use the explicit base URL");

    $expected_logout = "{$this->alt_base_url}{$this->default_handler_url}/Logout";
    $this->assertEquals($expected_logout, substr($logouturl, 0, strlen($expected_logout)), "The generated logout URL should use the explicit base URL");

  }

  public function testSessionState()
  {
    $shib = new BasicAuthenticator();

    // From setUp()...
    $idp = $_SERVER['Shib-Identity-Provider'];
    $logged_in_since = $_SERVER['Shib-Authentication-Instant'];

    $this->assertTrue($shib->hasSession());
    $this->assertEquals($idp, $shib->getIdPEntityId());
    $this->assertEquals(strtotime($logged_in_since), $shib->loggedInSince());
    $this->assertTrue($shib->loggedInWithMKey());

    // Check a non-expired session
    $this->assertFalse($shib->hasSessionTimedOut());
    // Check an expired session passing $maxAge = 1
    $this->assertTrue($shib->hasSessionTimedOut(1));

  }

  public function testSessionStateFromHeaders() {
    $shib = new BasicAuthenticator();
    $shib->setAttributeAccessMethod(BasicAuthenticator::UMN_ATTRS_FROM_HEADERS);

    $idp = $_SERVER['HTTP_SHIB_IDENTITY_PROVIDER'];
    $logged_in_since = $_SERVER['HTTP_SHIB_AUTHENTICATION_INSTANT'];
    $this->assertEquals($idp, $shib->getIdPEntityId());
    $this->assertEquals(strtotime($logged_in_since), $shib->loggedInSince());

    // Test for no session
    unset($_SERVER['HTTP_SHIB_IDENTITY_PROVIDER']);
    $shib = new BasicAuthenticator();
    $shib->setAttributeAccessMethod(BasicAuthenticator::UMN_ATTRS_FROM_HEADERS);
    $this->assertFalse($shib->hasSession());
  }

  public function testGetSingleAttributes()
  {
    // Single string attribute
    $shib = new BasicAuthenticator();
    $this->assertEquals('user@example.com', $shib->getAttributeValue('eppn'));

    // Delimited attribute returns the full string
    $this->assertEquals('one;two;three', $shib->getAttributeValue('multiAttribute'));

    // Non-existent, null
    $this->assertNull($shib->getAttributeValues('notexist'));
  }

  public function testGetSingleAttributesFromHeaders()
  {
    // Single string attribute
    $shib = new BasicAuthenticator();
    $shib->setAttributeAccessMethod(BasicAuthenticator::UMN_ATTRS_FROM_HEADERS);
    $this->assertEquals('user@example.com', $shib->getAttributeValue('eppn'));

    // Delimited attribute returns the full string
    $this->assertEquals('one;two;three', $shib->getAttributeValue('multiAttribute'));

    // Non-existent, null
    $this->assertNull($shib->getAttributeValues('notexist'));
  }

  public function testMultiAttributes()
  {
    $shib = new BasicAuthenticator();
    // Known multi attribute returns an array
    $this->assertEquals(array('one','two','three'), $shib->getAttributeValues('multiAttribute'));

    // Single value, non-delimited returns an array with one value
    $this->assertEquals(array('user'), $shib->getAttributeValues('uid'));

    // Non-existent, null
    $this->assertNull($shib->getAttributeValues('notexist'));
  }

  public function testMultiAttributesFromHeaders()
  {
    $shib = new BasicAuthenticator();
    $shib->setAttributeAccessMethod(BasicAuthenticator::UMN_ATTRS_FROM_HEADERS);

    // Known multi attribute returns an array
    $this->assertEquals(array('one','two','three'), $shib->getAttributeValues('multiAttribute'));

    // Single value, non-delimited returns an array with one value
    $this->assertEquals(array('user'), $shib->getAttributeValues('uid'));

    // Non-existent, null
    $this->assertNull($shib->getAttributeValues('notexist'));
  }
  public function testCustomEntityIdAccessors()
  {
    $entityId = 'https://example.com/shibboleth/IdP';
    $shib = new BasicAuthenticator();
    $shib->setCustomIdPEntityId($entityId);
    $this->assertEquals($entityId, $shib->getCustomIdPEntityId());
  }
  public function testCustomEntityIdSession()
  {
    $entityId = 'https://example.com/shibboleth/IdP';
    // Overwrite IdP in $_SERVER for this test method
    $_SERVER['Shib-Identity-Provider'] = $entityId;

    $shib = new BasicAuthenticator();
    $shib->setCustomIdPEntityId($entityId);

    $this->assertTrue($shib->hasSession());
  }
  public function testAttributePrefix()
  {
    $shib = new BasicAuthenticator();
    $shib->setAttributePrefix('PHPUNIT_');

    $this->assertNull($shib->getAttributeValue('uid'), "No prefixed uid attribute should be present");
    // Set a prefixed uid for this test method
    $_SERVER['PHPUNIT_uid'] = 'prefixed_uid';
    $shib = new BasicAuthenticator();
    $shib->setAttributePrefix('PHPUNIT_');
    $this->assertEquals('prefixed_uid', $shib->getAttributeValue('uid'), "The accessed attribute should be the prefixed one");

    $shib->setAttributeAccessMethod(BasicAuthenticator::UMN_ATTRS_FROM_HEADERS);
    $this->assertEquals('user', $shib->getAttributeValue('uid'), "When using HTTP headers, the attribute should not be accessed with a prefix");
  }
  public function testAlternateSourceArray()
  {
    $source = array('altattr' => 'alternate attribute value');
    $shib = new BasicAuthenticator(array(), array());
    $this->assertNull($shib->getAttributeValue('altattr'));

    $shib = new BasicAuthenticator(array(), array(), $source);
    $this->assertEquals('alternate attribute value', $shib->getAttributeValue('altattr'));
  }
  public function testMockNoEnvSet()
  {
    // The required environment vars aren't set, receiving a mock user
    // via $_GET should have no effect
    $_GET['UMNSHIB_MOCK_USER'] = 'user2';
    $shib = new BasicAuthenticator();
    $this->assertEquals('user', $shib->getAttributeValue('uid'));
    $this->assertFalse($shib->isMockUser());
  }
  /**
   * @expectedException \PHPUnit_Framework_Error_Warning
   */
  public function testBadArgSeparator()
  {
    // Set to a faulty value
    $er = error_reporting();
    error_reporting(E_ALL);
    $arg_s = ini_get('arg_separator.output');

    ini_set('arg_separator.output', '|');

    $shib = new BasicAuthenticator();
    $shib->buildLoginURL(array('target' => 'http://example.com', 'passive' => true, 'forceAuthn' => true));

    // Restore the old values
    error_reporting($er);
    ini_set('arg_separator.output', $arg_s);
  }
}
?>
