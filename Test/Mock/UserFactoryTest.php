<?php

namespace UMNShib\Basic\Test\Mock;

use UMNShib\Basic\Mock\UserFactory;

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
    echo __DIR__ . '/../Fixtures/MockUsers.php';
    $this->assertEquals(realpath(__DIR__ . '/../../Mock/Fixtures/MockUsers.php'), $factory->getUserFile());
  }
  public function testGetKnownUser()
  {
    $factory = new UserFactory("{$this->fixture_path}/good_mock.php");
    $user = $factory->getUser('user1');
    $this->assertTrue(true);
  }
  public function testGetUnknownUser()
  {
    $this->setExpectedException('UMNShib\Basic\Mock\Exception\UserNotFoundException');
    $factory = new UserFactory("{$this->fixture_path}/good_mock.php");
    $user = $factory->getUser('unknown');
  }
}
?>
