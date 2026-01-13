<?php
if (!isset($_SESSION)) {
    session_start();
}
include("../db.php");

if (isset($_SESSION["uid"])) {
    $uid = $_SESSION["uid"];
    $sql = "SELECT SUM(qty) AS total FROM cart WHERE user_id = '$uid'";
    $query = mysqli_query($conn, $sql);
    
    if ($query) {
        $row = mysqli_fetch_array($query);
        // Use legacy ternary instead of ?? operator
        echo ($row['total'] > 0) ? $row['total'] : "0";
    } else {
        echo "0";
    }
} else {
    echo "0";
}
?>
