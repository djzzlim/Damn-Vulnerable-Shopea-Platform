<?php
// Start the session to gain access to it
session_start();

// 1. Unset all session variables (uid, user_name, etc.)
$_SESSION = array();

// 2. Delete the session cookie from the browser
if (ini_get("session.use_cookies")) {
    $params = session_get_cookie_params();
    setcookie(session_name(), '', time() - 42000,
        $params["path"], $params["domain"],
        $params["secure"], $params["httponly"]
    );
}

// 3. Destroy the session on the server
session_destroy();

// 4. Redirect back to the home page or login page
header("Location: ../index.php");
exit();
?>
