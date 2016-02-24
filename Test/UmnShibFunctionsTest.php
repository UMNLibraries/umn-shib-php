<?php

use UMNShib\Basic\BasicAuthenticator;

class UmnShibFunctionsTest extends \PHPUnit_Framework_TestCase
{
  private $http_host = 'example.com';
  private $default_handler_url = '/Shibboleth.sso';
  private $alt_handler_url = '/shibboleth/Shibboleth.sso';
  private $request_uri = '/test/index.html?param=123';
  private $alt_request_uri ='/altdir/test/';

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
      'HTTP_MULTIATTRIBUTE' => 'one;two;three',
      'PREFIX_prefattr' => 'prefixed attribute'
    );
    $GLOBALS['_SERVER'] = array_merge($GLOBALS['_SERVER'], $shib_server);
    
    // Enforce correct arg separator in case prior test removes it
    ini_set('arg_separator.output', '&');
  }

  public function testLoginURL()
  {
    // Build a most basic login URL
    $url = umnshib_buildLoginURL();

    // It should begin with https:// followed by http_host followed by default_handler_url
    $expected_base = "https://{$this->http_host}{$this->default_handler_url}/Login";
    $this->assertEquals($expected_base, substr($url, 0, strlen($expected_base)), "The protocol, hostname, and Shibboleth handler should match");

    // It should also contain a urlencoded target= parameter with the full proto,host,request uri
    $expected_qs = "target=" . urlencode("https://{$this->http_host}{$this->request_uri}");
    $this->assertEquals($expected_qs, substr($url, -strlen($expected_qs)), "The generated URL should end with a urlencoded target= URL");

    // Build a login URL with isPassive
    $url = umnshib_buildLoginURL(array('passive' => true));
    $expected_qs_passive = "isPassive=true&" . $expected_qs;
    $this->assertEquals($expected_qs_passive, substr($url, -strlen($expected_qs_passive)), "The generated URL should begin with isPassive=true");

    // Mkey option
    $url = umnshib_buildLoginURL(array('mkey' => true));
    $expected_mkey = "authnContextClassRef=" . urlencode(BasicAuthenticator::UMN_MKEY_AUTHN_CONTEXT) . "&";
    $mkey_qs = preg_replace('/^' . preg_quote($expected_base, '/') . '\?/', '', $url);
    $this->assertEquals($expected_mkey, substr($mkey_qs, 0, strlen($expected_mkey)), "The generated URL should begin with an encoded authnContextClass for MKEY");

    // Multiple options (explicit target and forceAuthn)
    $expected_base_alt = "https://{$this->http_host}{$this->alt_request_uri}";
    $expected_qs_target = "target=" . urlencode($expected_base_alt);
    $expected_qs_force = "forceAuthn=true&";
    $url = umnshib_buildLoginURL(array('target' => $expected_base_alt, 'forceAuthn' => true));
    $this->assertTrue(strpos($url, $expected_qs_target) !== false, "The generated URL should contain the encoded explicit target");
    $this->assertTrue(strpos($url, $expected_qs_force) !== false, "The generated URL should contain a forceAuthn=true parameter");
  }

  public function testLogoutURL()
  {
    // Build a basic logout URL
    $url = umnshib_buildLogoutURL();

    // It should begin with https:// followed by http_host followed by default_handler_url and /Logout
    $expected_base = "https://{$this->http_host}{$this->default_handler_url}/Logout";
    $this->assertEquals($expected_base, substr($url, 0, strlen($expected_base)), "The protocol, hostname, and Shibboleth handler should match");

    // Verify the return= URL since logoutFromIdP is the default
    $expected_qs = "?return=" . urlencode(BasicAuthenticator::UMN_IDP_LOGOUT_URL);
    $this->assertEquals($expected_qs, substr($url, -strlen($expected_qs)), "A default logout URL should contain an encoded return to the IdP logout URL");

    // Build a SP-only logout, contains no query string, should match the original base URL
    $url = umnshib_buildLogoutURL(array('logoutFromIdP' => false));
    $this->assertEquals($expected_base, $url, "Without an IdP logout, the generated URL should have no query string");

    // Build an IdP logout with an explicit additional return URL
    $return_url = "https://{$this->http_host}{$this->alt_request_uri}";
    $url = umnshib_buildLogoutURL(array('logoutFromIdP' => true, 'return' => $return_url));

    $expected_return = "?return=" . urlencode(BasicAuthenticator::UMN_IDP_LOGOUT_URL . "?return={$return_url}");
    $this->assertEquals($expected_return, substr($url, -strlen($expected_return)), "The generated URL should contain an encoded IdP logout with an additional encoded return URL inside it");
  }

  public function testSessionState()
  {
    // From setUp()...
    $idp = $_SERVER['Shib-Identity-Provider'];
    $logged_in_since = $_SERVER['Shib-Authentication-Instant'];

    $this->assertTrue(umnshib_hasSession());
    $this->assertEquals($idp, umnshib_getIdPEntityId());
    $this->assertEquals(strtotime($logged_in_since), umnshib_loggedInSince());
    $this->assertTrue(umnshib_loggedInWithMKey());

    // Check a non-expired session
    $this->assertFalse(umnshib_hasSessionTimedOut());
    // Check an expired session passing $maxAge = 1
    $this->assertTrue(umnshib_hasSessionTimedOut(1));

    // Repeat these after setting for header access instead of Env access
    $idp = $_SERVER['HTTP_SHIB_IDENTITY_PROVIDER'];
    $logged_in_since = $_SERVER['HTTP_SHIB_AUTHENTICATION_INSTANT'];
    $this->assertEquals($idp, umnshib_getIdPEntityId(true));
    $this->assertEquals(strtotime($logged_in_since), umnshib_loggedInSince(true));

    // Test for no session
    unset($_SERVER['HTTP_SHIB_IDENTITY_PROVIDER']);
    $this->assertFalse(umnshib_hasSession(true));
  }

  public function testGetSingleAttributes()
  {
    // Single string attribute
    $this->assertEquals('user@example.com', umnshib_getAttributeValue('eppn'));

    // Delimited attribute returns the full string
    $this->assertEquals('one;two;three', umnshib_getAttributeValue('multiAttribute'));

    // Non-existent, null
    $this->assertNull(umnshib_getAttributeValues('notexist'));
  }

  public function testGetSingleAttributesFromHeaders()
  {
    // Single string attribute
    $this->assertEquals('user@example.com', umnshib_getAttributeValue('eppn', true));

    // Delimited attribute returns the full string
    $this->assertEquals('one;two;three', umnshib_getAttributeValue('multiAttribute', true));

    // Non-existent, null
    $this->assertNull(umnshib_getAttributeValues('notexist', true));
  }

  public function testMultiAttributes()
  {
    // Known multi attribute returns an array
    $this->assertEquals(array('one','two','three'), umnshib_getAttributeValues('multiAttribute'));
  
    // Single value, non-delimited returns an array with one value
    $this->assertEquals(array('user'), umnshib_getAttributeValues('uid'));

    // Non-existent, null
    $this->assertNull(umnshib_getAttributeValues('notexist'));
  }

  public function testMultiAttributesFromHeaders()
  {
    // Known multi attribute returns an array
    $this->assertEquals(array('one','two','three'), umnshib_getAttributeValues('multiAttribute', true));
  
    // Single value, non-delimited returns an array with one value
    $this->assertEquals(array('user'), umnshib_getAttributeValues('uid', true));

    // Non-existent, null
    $this->assertNull(umnshib_getAttributeValues('notexist', true));
  }

  public function testAttributePrefix()
  {
    $this->assertEquals('prefixed attribute', umnshib_getAttributeValue('prefattr', false, 'PREFIX_'));
  }
}
?>
