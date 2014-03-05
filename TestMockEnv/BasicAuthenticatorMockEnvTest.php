<?php
namespace UMNShib\Basic\Test;

use UMNShib\Basic\BasicAuthenticator;

class BasicAuthenticatorMockEnvTest extends \PHPUnit_Framework_TestCase
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
      'REQUEST_URI'
    );
    foreach ($keys as $key) {
      if (isset($_SERVER[$key])) unset($_SERVER[$key]);
    }
  }
  public function testMockUserEnvSet()
  {
    $shib = new BasicAuthenticator();
    
    $this->assertEquals('user1', $shib->getAttributeValue('uid'));
    $this->assertEmpty($shib->getAttributeValue('REMOTE_USER'));
  }
  public function testMockUserQueryString()
  {
    // Should overwrite user1 from the environment var
    $_GET['UMNSHIB_MOCK_USER'] = 'user2';
    $shib = new BasicAuthenticator();
    $this->assertEquals('user2', $shib->getAttributeValue('uid'));
    $this->assertEquals('user2', $shib->getAttributeValue('REMOTE_USER'));
  }
  public function testMockUserQueryStringUnknown()
  {
    // Unknown user should issue an E_USER_NOTICE instead of throwing an exception
    $this->setExpectedException('PHPUnit_Framework_Error_Notice');
    $_GET['UMNSHIB_MOCK_USER'] = 'baduser';
    $shib = new BasicAuthenticator();
  }
}
?>
