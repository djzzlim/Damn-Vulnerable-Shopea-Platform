<?php
session_start();
include("../db.php");
$uid = $_SESSION["uid"];

// Remove Item
if (isset($_POST["removeItem"])) {
    $pid = $_POST["remove_id"];
    $sql = "DELETE FROM cart WHERE p_id = '$pid' AND user_id = '$uid'";
    mysqli_query($conn, $sql);
    echo "Item Removed";
}

// Update Quantity
if (isset($_POST["updateItem"])) {
    $pid = $_POST["update_id"];
    $qty = $_POST["qty"];
    
    if ($qty <= 0) {
        $sql = "DELETE FROM cart WHERE p_id = '$pid' AND user_id = '$uid'";
    } else {
        $sql = "UPDATE cart SET qty = '$qty' WHERE p_id = '$pid' AND user_id = '$uid'";
    }
    mysqli_query($conn, $sql);
    echo "Cart Updated";
}
?>
