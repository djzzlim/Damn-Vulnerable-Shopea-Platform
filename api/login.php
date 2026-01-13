<?php
session_start(); // Vulnerable: No regeneration for Session Fixation
include("../db.php");

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $email = $_POST['email'];
    $password = $_POST['password'];

    // Hardcoded Admin Credentials
    $admin_email = "admin@technovation.local";
    $admin_pass = "Abcd1234";

    // Check for Hardcoded Admin first
    if ($email === $admin_email && $password === $admin_pass) {
        // Manually set session for the backdoor
        $_SESSION['uid'] = 0; // Assuming 1 is the admin ID
        $_SESSION['user_name'] = "Admin"; 
        header("Location: ../admin.php");
        exit();
    }

    // Standard Login Logic (SQL Injection Vulnerability remains)
    $sql = "SELECT user_id, first_name FROM users WHERE email = '$email' AND password = '" . md5($password) . "'";
    $result = $conn->query($sql);

    if ($result && $result->num_rows > 0) {
        $row = $result->fetch_assoc();
        $_SESSION['uid'] = $row['user_id'];
        $_SESSION['user_name'] = $row['first_name']; 
        header("Location: ../index.php");
    } else {
        $_SESSION['error_msg'] = "Invalid Login"; 
        header("Location: " . $_SERVER['HTTP_REFERER']); 
    }
    exit();
}
