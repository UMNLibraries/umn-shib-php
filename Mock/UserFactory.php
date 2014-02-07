<?php

namespace UMNShib\Basic\Mock;

use UMNShib\Basic\BasicAuthenticator;

class UserFactory
{
  protected $users = array();
  protected $userfile = '';

  /**
   * Receives a file path to load Mock Users
   * 
   * @param string|null $userfile PHP file returning a user array, or the default file if null
   * @access public
   * @return bool
   */
  public function __construct($userfile = null)
  {
    if (empty($userfile)) {
      $userfile = __DIR__ . '/Fixtures/MockUsers.php';
    }
    if (!file_exists($userfile)) {
      throw new Exception\UserFileNotFoundException("The requested Mock User file $userfile not found");
    }

    // $userfile should define and return a 2D array
    // indexed by username
    $users = include($userfile);
    if (!is_array($users)) {
      throw new \UnexpectedValueException("$userfile must define and return an array");
    }
    if (!$this->validateUserArray($users)) {
      throw new \UnexpectedValueException("$userfile array must have contain string keys and sub-arrays");
    }

    $this->users = $users;
    $this->userfile = realpath($userfile);
    return;
  }
  /**
   * Return the user having the requested username
   * 
   * @param string $username
   * @access public
   * @return UMNShib\Basic\Mock\User
   */
  public function getUser($username)
  {
    if (array_key_exists($username, $this->users)) {
      return new User($username);
    }
    else {
      throw new Exception\UserNotFoundException();
    }
  }
  /**
   * Return a random user from the Mock users list
   * 
   * @access public
   * @return UMNShib\Basic\Mock\User
   */
  public function getRandomUser()
  {
    return new User(array_rand(array_keys($this->users)));
  }
  /**
   * Return the currently loaded mock user file
   * 
   * @access public
   * @return string
   */
  public function getUserFile()
  {
    return $this->userfile;
  }
  protected function validateUserArray(array $users)
  {
    // Make sure all keys are string and have sub-arrays
    foreach ($users as $key => $array) {
      if (!is_string($key) || ctype_digit(strval($key)) || !is_array($array)) {
        return false;
      }
    }
    return true;
  }
}
?>
