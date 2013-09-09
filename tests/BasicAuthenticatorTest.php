<?php

namespace UMNShib\BasicAuthenticator;

require_once(APPDIR . '/BasicAuthenticator.php');

class BasicAuthenticatorTest extends \PHPUnit_Framework_TestCase
{
  private $http_host = 'example.com';
  private $default_handler_url = '/Shibboleth.sso';
  private $alt_handler_url = '/shibboleth/Shibboleth.sso';
  private $request_uri = '/test/index.html?param=123';
  private $alt_request_uri ='/altdir/test/';

  public function setUp()
  {
    // Initialize _SERVER superglobal since this is a CLI run
    $_SERVER = array(
      'HTTP_HOST' => $this->http_host,
      'REQUEST_URI' => $this->request_uri,
      'Shib-Identity-Provider' => BasicAuthenticator::UMN_IDP_ENTITY_ID,
      'HTTP_SHIB_IDENTITY_PROVIDER' => BasicAuthenticator::UMN_TEST_IDP_ENTITY_ID, // Different for test distinction
      'Shib-Authentication-Instant' => date('c', time() - 1800),
      'HTTP_SHIB_AUTHENTICATION_INSTANT' => date('c', time() - 3600), // Earlier login in the header (for test distinction)
      'Shib-AuthnContext-Class' => BasicAuthenticator::UMN_MKEY_AUTHN_CONTEXT,
      'REMOTE_USER' => 'user@example.com',
      'eppn' => 'user@example.com',
      'uid' => 'user',
      'multiAttribute' => 'one;two;three'
    );
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
    $expected_qs_passive = $expected_qs . "&isPassive=true";
    $this->assertEquals($expected_qs_passive, substr($url, -strlen($expected_qs_passive)), "The generated URL should end with isPassive=true");

    // Mkey option
    $url = $shib->buildLoginURL(array('mkey' => true));
    $expected_mkey = "&authnContextClassRef=" . urlencode(BasicAuthenticator::UMN_MKEY_AUTHN_CONTEXT);
    $this->assertEquals($expected_mkey, substr($url, -strlen($expected_mkey)), "The generated URL should end with an encoded authnContextClass for MKEY");

    // Multiple options (explicit target and forceAuthn)
    $expected_base_alt = "https://{$this->http_host}{$this->alt_request_uri}";
    $expected_qs_target = "target=" . urlencode($expected_base_alt);
    $expected_qs_force = "&forceAuthn=true";
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

    // Repeat these after setting for header access instead of Env access
    $shib->setAttributeAccessMethod(BasicAuthenticator::UMN_ATTRS_FROM_HEADERS);

    $idp = $_SERVER['HTTP_SHIB_IDENTITY_PROVIDER'];
    $logged_in_since = $_SERVER['HTTP_SHIB_AUTHENTICATION_INSTANT'];
    $this->assertEquals($idp, $shib->getIdPEntityId());
    $this->assertEquals(strtotime($logged_in_since), $shib->loggedInSince());

    // Test for no session
    unset($_SERVER['HTTP_SHIB_IDENTITY_PROVIDER']);
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
}
?>
