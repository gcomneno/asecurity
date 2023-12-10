<?php

namespace gcc\asecurity\test;

require_once __DIR__ . '/../vendor/autoload.php';

use PHPUnit\Framework\TestCase;
use gcc\asecurity\PasswordUtils;

class PasswordUtilsTest extends TestCase
{
    public function testGenerateSalt()
    {
        $salt = PasswordUtils::generateSalt();
        $this->assertMatchesRegularExpression('/^\$2y\$12\$\w{22}$/', $salt);
    }

    public function testHashPassword()
    {
        $password = 'testPassword';
        $salt = PasswordUtils::generateSalt();
        $hashedPassword = PasswordUtils::hashPassword($password, $salt);
        
        $this->assertNotEmpty($hashedPassword);
        $this->assertTrue(password_verify($password, $hashedPassword));
    }
}
