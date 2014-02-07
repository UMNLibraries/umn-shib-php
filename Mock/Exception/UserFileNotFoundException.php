<?php

namespace UMNShib\Basic\Mock\Exception;

class UserFileNotFoundException extends \Exception
{
  protected $message = 'The requested Mock User file was not found';
}
?>
