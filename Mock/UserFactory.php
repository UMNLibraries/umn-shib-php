<?php

namespace UMNShib\Basic\Mock;

require_once('UserFactoryInterface.php');

use UMNShib\Basic\BasicAuthenticator;

/**
 * Retrieval factory for mock Shibboleth user requests
 * 
 * @package UMNShib\Basic
 * @copyright [Copyright]
 * @author Michael Berkowski <mjb@umn.edu> 
 * @license [License]
 */
class UserFactory
{
  protected $users = array();
  protected $userFile = '';
  protected $commonAttributes = array();

  /**
   * Receives a file path to load Mock Users
   * 
   * @param string|null $userFile PHP file returning a user array, or the default file if null
   * @access public
   * @return bool
   */
  public function __construct($userFile = null)
  {
    if (empty($userFile)) {
      $userFile = __DIR__ . '/Fixtures/MockUsers.php';
    }
    if (!file_exists($userFile)) {
      throw new Exception\UserFileNotFoundException("The requested Mock User file $userFile not found");
    }

    // $userFile should define and return a 2D array
    // indexed by username
    $users = include($userFile);
    if (!is_array($users)) {
      throw new \UnexpectedValueException("$userFile must define and return an array");
    }
    if (!$this->validateUserArray($users)) {
      throw new \UnexpectedValueException("$userFile array must have contain string keys and sub-arrays");
    }

    $this->users = $users;
    $this->userFile = realpath($userFile);
    return;
  }
  /**
   * Return the user having the requested username
   * 
   * @param string $username
   * @access public
   * @return array
   */
  public function getUser($username)
  {
    if (array_key_exists($username, $this->users)) {
      return $this->users[$username];
    }
    else {
      throw new Exception\UserNotFoundException();
    }
  }
  /**
   * Return a random user from the Mock users list
   * 
   * @access public
   * @return array
   */
  public function getRandomUser()
  {
    return $this->users[array_rand($this->users)];
  }
  /**
   * Return the currently loaded mock user file
   * 
   * @access public
   * @return string
   */
  public function getUserFile()
  {
    return $this->userFile;
  }
  /**
   * Setup a set of attributes related to the session
   * Any of these may be overridden by array values in the mock user.
   * 
   * @access public
   * @return void
   */
  public function setCommonAttributes()
  {
    $this->commonAttributes = array(
      'Shib-Identity-Provider' => BasicAuthenticator::UMN_IDP_ENTITY_ID,
      'Shib-Authentication-Method' => 'urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified',
      'Shib-AuthnContext-Class' => 'urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified',
      'Shib-Application-ID' => 'default',
      'Shib-Session-Index' => 'abcdefg',
      'Shib-Session-ID' => '_' . md5(microtime() . rand()),
      'Shib-Authentication-Instant' => date('c')
    );
    return;
  }
  /**
   * Fixate a mock user into the $_SERVER superglobal
   * 
   * @param array $user_params
   * @param string $use_headers Write attributes into HTTP_ headers
   * @access public
   * @return bool
   */
  public function setUser(array $user_params, $use_headers = false)
  {
    $this->setCommonAttributes();
    foreach (array_merge($this->commonAttributes, $user_params) as $attr => $value) {
      if ($use_headers) {
        $attr = BasicAuthenticator::convertToHTTPHeaderName($attr);
      }
      $_SERVER[$attr] = $value;
    }
  }
  /**
   * Make sure all keys are strings and have sub-arrays
   * 
   * @param array $users 
   * @access protected
   * @return bool
   */
  protected function validateUserArray(array $users)
  {
    foreach ($users as $key => $array) {
      if (!is_string($key) || ctype_digit(strval($key)) || !is_array($array)) {
        return false;
      }
    }
    return true;
  }
}
?>
