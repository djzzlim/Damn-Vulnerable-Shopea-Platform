<?php
session_start();
include("../db.php");

if (!isset($conn)) {
    die("Debug Error: Connection variable not found. Check if db.php is included correctly.");
}

if (!isset($_SESSION['uid'])) {
    header("location: ../index.php");
    exit();
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $user_id = $_SESSION['uid'];
    $password = $_POST['password'];
    
    $hashed_password = md5($password); 

    $sql = "UPDATE users SET password = ? WHERE user_id = ?";
    $stmt = mysqli_prepare($conn, $sql);
    
    if ($stmt) {
        mysqli_stmt_bind_param($stmt, "si", $hashed_password, $user_id);
        
        if (mysqli_stmt_execute($stmt)) {
            header("location: ../changepassword.php?status=success");
            exit();
        } else {
            die("Execute failed: " . mysqli_stmt_error($stmt));
        }
        mysqli_stmt_close($stmt);
    } else {
        die("Prepare failed: " . mysqli_error($conn));
    }
}
mysqli_close($conn);
?>
