<?php

class PasswordVerifier {

    /**
     * String user password
     * @var type string
     */
    protected $password;

    /**
     * Pbkdf2 Hash stored in database
     * @var type string
     */
    protected $hash;

    public function __construct(string $password, string $hash) {
        $this->password = $password;
        $this->hash = $hash;
    }

    /**
     * Comparing string user password with pbkdf2 hash stored in database
     * @return type bool
     * True - equal passwords, False - not equal passwords
     * @throws Exception
     */
    public function verify(): bool {
        $pieces = explode('$', $this->hash);
        if (count($pieces) !== 4) {
            throw new Exception("Illegal hash format");
        }
        list($header, $iter, $salt, $hash) = $pieces;
        if (preg_match('#^pbkdf2_([a-z0-9A-Z]+)$#', $header, $matches)) {
            $algo = $matches[1];
        } else {
            throw new Exception(sprintf("Bad header (%s)", $header));
        }
        if (!in_array($algo, hash_algos())) {
            throw new Exception(sprintf("Illegal hash algorithm (%s)", $algo));
        }

        $calc = hash_pbkdf2(
                $algo, $this->password, $salt, (int) $iter, 32, true
        );
        return hash_equals($calc, base64_decode($hash));
    }

}
