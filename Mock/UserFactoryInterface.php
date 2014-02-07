<?php

namespace UMNShib\Basic\Mock;

use UMNShib\Basic\BasicAuthenticator;

interface UserFactoryInterface
{
  public function __construct($userfile = null);
  public function getUser($username);
  public function getRandomUser();
}
?>
