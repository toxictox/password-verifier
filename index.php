<?php

require ('components/DB.php');
require ('components/PasswordVerifier.php');

$db = Database::getInstance();
$mysqli = $db->getConnection();


$username = "sagar4321";
$password = "121212mm";

$result = $mysqli->query("SELECT * FROM auth_user_tmp WHERE username='{$username}'");

$userData = $result->fetch_object();

/* usage example */
$verifier = new PasswordVerifier($password, $userData->password);

if (true === $verifier->verify()) {
    $mysqli->query("UPDATE auth_user_tmp SET password_changed=1, password='" . md5($password) . "' WHERE username='{$userData->username}'");
    echo 'Generated new md5 password hash: '.md5($password);
} else {
    echo 'Incorrect password!';
}