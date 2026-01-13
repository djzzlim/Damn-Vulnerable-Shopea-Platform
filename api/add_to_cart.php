<?php
// Enable error reporting to find hidden bugs
error_reporting(E_ALL);
ini_set('display_errors', 1);

session_start();
include("../db.php");

if (isset($_POST["addToCart"])) {
    
    // Check if session exists
    if (!isset($_SESSION["uid"])) {
        echo "Error: You must be logged in to add items.";
        exit();
    }

    $p_id = mysqli_real_escape_string($conn, $_POST["proId"]);
    $user_id = $_SESSION["uid"];

    // Check if item already exists
    $check_sql = "SELECT cart_id FROM cart WHERE p_id = '$p_id' AND user_id = '$user_id'";
    $run_check = mysqli_query($conn, $check_sql);

    if (mysqli_num_rows($run_check) > 0) {
        $update_sql = "UPDATE cart SET qty = qty + 1 WHERE p_id = '$p_id' AND user_id = '$user_id'";
        if(mysqli_query($conn, $update_sql)){
            echo "Item quantity updated!";
        } else {
            echo "Error updating quantity: " . mysqli_error($conn);
        }
    } else {
        $insert_sql = "INSERT INTO cart (p_id, user_id, qty) VALUES ('$p_id', '$user_id', 1)";
        if(mysqli_query($conn, $insert_sql)){
            echo "Item added to cart!";
        } else {
            echo "Error adding item: " . mysqli_error($conn);
        }
    }
} else {
    echo "No data received by API.";
}
?>
