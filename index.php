<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);
session_start();
include("db.php");
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Shopea Online</title>
    <link rel="stylesheet" href="assets/css/bootstrap.min.css">
    <script src="assets/js/jquery-3.1.1.js"></script>
    <script src="assets/js/bootstrap.min.js"></script>
    <style>
        .list-group-item.active { background-color: #337ab7; border-color: #2e6da4; }
        .product-box { border: 1px solid #ddd; margin-bottom: 20px; border-radius: 4px; }
        .product-name-header { background-color: #e3f2fd; padding: 8px; border-bottom: 1px solid #ddd; color: #31708f; font-weight: bold; height: 40px; overflow: hidden; }
        .product-body { padding: 15px; text-align: center; }
        .product-footer { padding: 10px; border-top: 1px solid #eee; }
        .price { color: #337ab7; font-size: 18px; font-weight: bold; }
    </style>
</head>
<body>

    <?php include('includes/menubar.php'); ?>

    <div class="container-fluid" style="margin-top: 20px; margin-left: 10%; margin-right: 10%">
        <div class="row">
            <div class="col-md-3">
                <div class="list-group">
                    <a href="index.php" class="list-group-item active">Categories</a>
                    <?php
                        $cat_query = "SELECT * FROM categories";
                        $run_query = mysqli_query($conn, $cat_query);
                        while($row = mysqli_fetch_array($run_query)){
                            $id = $row['cat_id'];
                            $title = $row['cat_title'];
                            echo "<a href='index.php?cat=$id' class='list-group-item'>$title</a>";
                        }
                    ?>
                    <a href="index.php" class="list-group-item active" style="margin-top: 10px;">Brands</a>
                    <?php
                        $brand_query = "SELECT * FROM brands";
                        $run_query = mysqli_query($conn, $brand_query);
                        while($row = mysqli_fetch_array($run_query)){
                            $id = $row['brand_id'];
                            $title = $row['brand_title'];
                            echo "<a href='index.php?brand=$id' class='list-group-item'>$title</a>";
                        }
                    ?>
                </div>
            </div>

            <div class="col-md-9">
                <h3 style="margin-top: 0; padding-bottom: 10px; border-bottom: 1px solid #eee;">
                    <?php
                        if(isset($_GET['search'])) { echo "Search Results for: " . htmlspecialchars($_GET['search']); }
                        elseif(isset($_GET['cat'])) { echo "Category Products"; }
                        elseif(isset($_GET['brand'])) { echo "Brand Products"; }
                        else { echo "All Products"; }
                    ?>
                </h3>
                <div class="row">
                    <?php
                        $get_products = "SELECT * FROM products";

                        if(isset($_GET['search'])) {
                            $keyword = $_GET['search'];
			    $get_products = "SELECT * FROM products WHERE product_title LIKE '%$keyword%'";
                        }
                        elseif(isset($_GET['cat'])){
                            $cat_id = mysqli_real_escape_string($conn, $_GET['cat']);
                            $get_products = "SELECT * FROM products WHERE product_cat = '$cat_id'";
                        }
                        elseif(isset($_GET['brand'])){
                            $brand_id = mysqli_real_escape_string($conn, $_GET['brand']);
                            $get_products = "SELECT * FROM products WHERE product_brand = '$brand_id'";
                        }

                        $run_products = mysqli_query($conn, $get_products);

                        // ERROR HANDLING: If the query fails, show the database error message
                        if (!$run_products) {
                            echo "<div class='alert alert-danger'>
                                    <strong>SQL Error:</strong> " . mysqli_error($conn) . "<br>
                                    <strong>Query:</strong> $get_products
                                  </div>";
                        } else {
                            if (mysqli_num_rows($run_products) > 0) {
                                while($row = mysqli_fetch_array($run_products)){
                                    $pid = $row['product_id'];
                                    $title = $row['product_title'];
                                    $price = $row['product_price'];
                                    $img = $row['product_image'];

                                    echo "
                                    <div class='col-md-4'>
                                        <div class='product-box'>
                                            <div class='product-name-header'>$title</div>
                                            <div class='product-body'>
                                                <img src='assets/images/$img' alt='$title' style='height: 200px; max-width: 100%; object-fit: contain;'>
                                            </div>
                                            <div class='product-footer'>
                                                <span class='price'>$price</span>
                                                <button class='btn btn-danger btn-sm pull-right add-to-cart' pid='$pid'>Add to Cart</button>
                                                <div class='clearfix'></div>
                                            </div>
                                        </div>
                                    </div>";
                                }
                            } else {
                                echo "<div class='col-md-12'><div class='alert alert-warning'>No products found matching your criteria.</div></div>";
                            }
                        }
                    ?>
                </div>
            </div>
        </div>
    </div>

<script>
$(document).ready(function() {
    $(document).on('click', '.add-to-cart', function(e) {
        e.preventDefault();
        var pid = $(this).attr('pid');
        $.ajax({
            url: "api/add_to_cart.php",
            method: "POST",
            data: { addToCart: 1, proId: pid },
            success: function(data) {
                alert(data);
                $.get("api/get_cart_count.php", function(count) {
                    $('.cart-badge').text(count);
                });
            }
        });
    });
});
</script>
</body>
</html>
