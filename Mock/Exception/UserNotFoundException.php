<?php

namespace UMNShib\Basic\Mock\Exception;

class UserNotFoundException extends \Exception
{
  protected $message = 'The requested Mock User was not found';
}
?>
