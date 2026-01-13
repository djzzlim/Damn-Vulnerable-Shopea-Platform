<?php
include("../db.php"); 

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $email = $_POST['email'];
    $mob   = $_POST['mobile'];
    $addr1 = $_POST['address1'];
    $addr2 = $_POST['address2'];
    $pass  = md5($_POST['password']);
    $lname = $_POST['last_name'];
    $fname = $_POST['first_name'];

    // 1. CHECKER: See if the email already exists
    $checkEmail = $conn->prepare("SELECT email FROM users WHERE email = ?");
    $checkEmail->bind_param("s", $email);
    $checkEmail->execute();
    $checkEmail->store_result();

    if ($checkEmail->num_rows > 0) {
        // Email exists - redirect with an error status
        header("Location: ../registration.php?status=email_exists");
    } else {
        // 2. PROCEED: Email is unique, perform the insertion
        $query = "INSERT INTO users (email, mobile, address1, address2, password, last_name, first_name) VALUES (?, ?, ?, ?, ?, ?, ?)";
        $stmt = $conn->prepare($query);
        $stmt->bind_param("sssssss", $email, $mob, $addr1, $addr2, $pass, $lname, $fname);

        if ($stmt->execute()) {
            header("Location: ../registration.php?status=success");
        } else {
            header("Location: ../registration.php?status=fail");
        }
        $stmt->close();
    }
    $checkEmail->close();
    $conn->close();
}
?>
