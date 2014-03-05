<?php

namespace UMNShib\Basic\Test\Mock;

use UMNShib\Basic\Mock\UserFactory;
use UMNShib\Basic\BasicAuthenticator;

class UserFactoryTest extends \PHPUnit_Framework_TestCase
{
  private $fixture_path = '';
  public function setUp()
  {
    $this->fixture_path = __DIR__ . '/../Fixtures/Mock';
  }
  public function testGoodUserFile()
  {
    $factory = new UserFactory("{$this->fixture_path}/good_mock.php");
  }
  public function testNotFoundUserFile()
  {
    $this->setExpectedException('UMNShib\Basic\Mock\Exception\UserFileNotFoundException');
    $factory = new UserFactory("{$this->fixture_path}/not_exist.php");
  }
  public function testBadUserFileNonAssoc()
  {
    $this->setExpectedException('UnexpectedValueException');
    $factory = new UserFactory("{$this->fixture_path}/bad_mock_nonassoc.php");

  }
  public function testBadUserFileNonArray()
  {
    $this->setExpectedException('UnexpectedValueException');
    $factory = new UserFactory("{$this->fixture_path}/bad_mock_nonarray.php");
  }
  public function testDefaultUserFile()
  {
    $factory = new UserFactory();
    $this->assertEquals(realpath(__DIR__ . '/../../Mock/Fixtures/MockUsers.php'), $factory->getUserFile());
  }
  public function testGetKnownUser()
  {
    $factory = new UserFactory("{$this->fixture_path}/good_mock.php");
    $user = $factory->getUser('user1');
    $this->assertEquals('user1', $user['uid']);
  }
  public function testGetUnknownUser()
  {
    $this->setExpectedException('UMNShib\Basic\Mock\Exception\UserNotFoundException');
    $factory = new UserFactory("{$this->fixture_path}/good_mock.php");
    $user = $factory->getUser('unknown');
  }
  public function testGetRandomUser()
  {
    $factory = new UserFactory("{$this->fixture_path}/good_mock.php");
    // Get 1000 random users and make sure more than one mock user was selected
    // Of course I know this isn't a great test, but if you get the same value
    // from array_rand() on 1k tries, you're either really lucky, or the good_mock.php
    // file needs attention. It should have at least 2 users defined.
    $usernames = array();
    foreach (range(1,1000) as $i) {
      $user = $factory->getRandomUser();
      $usernames[] = $user['uid'];
    }
    // After 1000 iterations there should be more than one unique name
    // in our array.
    $this->assertGreaterThan(1, count(array_unique($usernames)));
  }
  /**
   * @runInSeparateProcess
   *
   * Runs in another process since $_SERVER was likely polluted by other tests
   */
  public function testSetUserNoHeaders()
  {
    $user = array(
      'uid' => 'mockuser',
      'eppn' => 'mockuser@exmaple.com'
    );

    $factory = new UserFactory("{$this->fixture_path}/good_mock.php");
    $factory->setUser($user);

    // All the $user array keys should have been transferred to $_SERVER
    foreach ($user as $attr => $value) {
      $this->assertArrayHasKey($attr, $_SERVER);
      $this->assertEquals($user[$attr], $_SERVER[$attr]);
    }
  }
  /**
   * @runInSeparateProcess
   */
  public function testSetUserHeaders()
  {
    $user = array(
      'uid' => 'mockuser',
      'eppn' => 'mockuser@exmaple.com'
    );

    $factory = new UserFactory("{$this->fixture_path}/good_mock.php");
    $factory->setUser($user, true);

    // All the $user array keys should have been transferred to $_SERVER
    // as HTTP_ headers
    foreach ($user as $attr => $value) {
      $server_attr = BasicAuthenticator::convertToHTTPHeaderName($attr);
      $this->assertArrayHasKey($server_attr, $_SERVER);
      $this->assertEquals($user[$attr], $_SERVER[$server_attr]);
    }
  }
}
?>
