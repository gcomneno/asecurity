<?php

namespace gcc\asecurity;

/**
 * Class PasswordUtils
 *
 * Utility class for password-related operations.
 */
class PasswordUtils
{
    /**
     * Generate a random salt for password hashing.
     *
     * @param int $cost The cost parameter for bcrypt. Default is 12.
     * @return string The generated salt.
     */
    public static function generateSalt($cost = 12)
    {
        $salt = sprintf('$2y$%02d$', $cost);
        $salt .= substr(bin2hex(random_bytes(22)), 0, 22);
        return $salt;
    }

    /**
     * Hash the given password with the provided salt using bcrypt.
     *
     * @param string $password The password to hash.
     * @param string $salt The salt to use for hashing.
     * @return string The hashed password.
     */
    public static function hashPassword($password, $salt)
    {
        $hashedPassword = crypt($password, $salt);
        return $hashedPassword;
    }

     /**
     * Hide user input on the screen when entering a password.
     *
     * @return string The user input without displaying characters on the screen.
     */
    public static function hideInput()
    {
        if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
            // For Windows, use a fallback method (may not work in all environments)
            return trim(stream_get_contents(STDIN));
        } else {
            // For UNIX-like systems, use stty to turn off echoing
            system('stty -echo');
            $input = trim(fgets(STDIN));
            system('stty echo'); // Turn echoing back on
            return $input;
        }
    }

    /**
     * Generate a password by taking user input and displaying hashed password and salt.
     * Note: This method is currently private and not used in the provided code.
     * 
     * @return void
     */
    private function generatePassword()
    {
        // Get user input for the password without showing characters on the screen
        echo "Enter your password: ";
        $rawPassword = $this->hideInput();
        echo "\n";

        // Generate a random salt with cost factor 12 (adjustable)
        $salt = $this->generateSalt();

        // Hash the password with the salt using bcrypt
        $hashedPassword = $this->hashPassword($rawPassword, $salt);

        // Print the hashed password and salt
        echo "Hashed Password: " . $hashedPassword . "\n";
        echo "Salt: " . $salt . "\n";
    }
}
