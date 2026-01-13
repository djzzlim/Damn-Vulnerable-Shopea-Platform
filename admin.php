<?php
if (!isset($_SESSION)) { session_start(); }
include("db.php");

if (!isset($_SESSION['uid'])) { 
    header("Location: index.php");
    exit(); 
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Shopea Admin - Dashboard</title>
    <link rel="stylesheet" href="assets/css/bootstrap.min.css">
    <script src="assets/js/jquery-3.1.1.js"></script>
    <script src="assets/js/bootstrap.min.js"></script>

<style>
    .product-table td img {
        display: block;
        margin-left: auto;
        margin-right: auto;
    }

    .product-table td {
        vertical-align: middle !important;
    }
</style>

</head>
<body>
    <?php include('includes/menubar.php'); ?>

    <div class="container" style="margin-top: 30px;">
        <h2>Admin Management Dashboard</h2>
        <hr>

        <ul class="nav nav-tabs" role="tablist">
            <li class="active"><a href="#products" role="tab" data-toggle="tab">Manage Products</a></li>
            <li><a href="#categories" role="tab" data-toggle="tab">Categories</a></li>
            <li><a href="#brands" role="tab" data-toggle="tab">Brands</a></li>
        </ul>

        <div class="tab-content" style="margin-top: 20px;">
            <div class="tab-pane active" id="products">
                <button class="btn btn-primary pull-right" data-toggle="modal" data-target="#addProductModal">Add New Product</button>
                <h3>Products List</h3>
                <table class="table table-bordered table-striped product-table">
                    <thead>
                        <tr>
                            <th>ID</th><th>Image</th><th>Title</th><th>Price</th><th>Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php
                        $p_res = mysqli_query($conn, "SELECT * FROM products");
                        while($p = mysqli_fetch_array($p_res)) {
                            $p_data = json_encode($p);
                            echo "<tr>
                                    <td>{$p['product_id']}</td>
                                    <td><img src='assets/images/{$p['product_image']}' width='80' style='border: 2px solid #ddd; border-radius: 4px; padding: 2px;'></td>
                                    <td>{$p['product_title']}</td>
                                    <td>\${$p['product_price']}</td>
                                    <td>
                                        <button class='btn btn-warning btn-xs edit-product-btn' data-info='".htmlspecialchars($p_data, ENT_QUOTES)."'>Edit</button>
                                        <a href='api/admin_actions.php?del_pro={$p['product_id']}' class='btn btn-danger btn-xs' onclick='return confirm(\"Delete product?\")'>Delete</a>
                                    </td>
                                  </tr>";
                        }
                        ?>
                    </tbody>
                </table>
            </div>

            <div class="tab-pane" id="categories">
                <form action="api/admin_actions.php" method="POST" class="form-inline">
                    <input type="text" name="cat_title" class="form-control" placeholder="New Category Name" required>
                    <button type="submit" name="add_cat" class="btn btn-success">Add Category</button>
                </form>
                <hr>
                <table class="table table-bordered">
		    <thead>
                        <tr>
                            <th>Categories</th><th>Action</th>
                        </tr>
                    </thead>
                    <?php
                    $c_res = mysqli_query($conn, "SELECT * FROM categories");
                    while($c = mysqli_fetch_array($c_res)) {
                        echo "<tr>
                                <td>{$c['cat_title']}</td>
                                <td style='width: 10px; white-space: nowrap;'><a href='api/admin_actions.php?del_cat={$c['cat_id']}' class='btn btn-danger btn-xs'>Remove</a></td>
                              </tr>";
                    }
                    ?>
                </table>
            </div>

            <div class="tab-pane" id="brands">
                <form action="api/admin_actions.php" method="POST" class="form-inline">
                    <input type="text" name="brand_title" class="form-control" placeholder="New Brand Name" required>
                    <button type="submit" name="add_brand" class="btn btn-success">Add Brand</button>
                </form>
                <hr>
                <table class="table table-bordered">
                    <thead>
                        <tr>
                            <th>Brands</th><th>Action</th>
                        </tr>
                    </thead>

                    <?php
                    $b_res = mysqli_query($conn, "SELECT * FROM brands");
                    while($b = mysqli_fetch_array($b_res)) {
                        echo "<tr>
                                <td>{$b['brand_title']}</td>
                                <td style='width: 10px; white-space: nowrap;'><a href='api/admin_actions.php?del_brand={$b['brand_id']}' class='btn btn-danger btn-xs'>Remove</a></td>
                              </tr>";
                    }
                    ?>
                </table>
            </div>
        </div>
    </div>

    <div class="modal fade" id="addProductModal" role="dialog">
        <div class="modal-dialog">
            <div class="modal-content">
                <form action="api/admin_actions.php" method="POST" enctype="multipart/form-data">
                    <div class="modal-header"><h4 class="modal-title">Add New Product</h4></div>
                    <div class="modal-body">
                        <input type="text" name="pro_title" class="form-control" placeholder="Product Title" required><br>
			<input type="number" name="pro_price" class="form-control" placeholder="Price" step="0.01" required><br>
                        <select name="pro_cat" class="form-control">
                            <?php 
                            $cr = mysqli_query($conn, "SELECT * FROM categories");
                            while($c = mysqli_fetch_array($cr)) echo "<option value='{$c['cat_id']}'>{$c['cat_title']}</option>";
                            ?>
                        </select><br>
                        <select name="pro_brand" class="form-control">
                            <?php 
                            $br = mysqli_query($conn, "SELECT * FROM brands");
                            while($b = mysqli_fetch_array($br)) echo "<option value='{$b['brand_id']}'>{$b['brand_title']}</option>";
                            ?>
                        </select><br>
                        <label>Product Image</label>
                        <input type="file" name="pro_img" required>
                    </div>
                    <div class="modal-footer">
                        <button type="submit" name="add_pro" class="btn btn-primary">Save Product</button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <div class="modal fade" id="editProductModal" role="dialog">
        <div class="modal-dialog">
            <div class="modal-content">
                <form action="api/admin_actions.php" method="POST" enctype="multipart/form-data">
                    <div class="modal-header"><h4 class="modal-title">Edit Product</h4></div>
                    <div class="modal-body">
                        <input type="hidden" name="update_id" id="edit_pro_id">
                        <label>Product Title</label>
                        <input type="text" name="pro_title" id="edit_pro_title" class="form-control" required><br>
                        <label>Price</label>
			<input type="number" name="pro_price" id="edit_pro_price" class="form-control" step="0.01" required><br>
                        <label>Category</label>
                        <select name="pro_cat" id="edit_pro_cat" class="form-control">
                            <?php 
                            $cr = mysqli_query($conn, "SELECT * FROM categories");
                            while($c = mysqli_fetch_array($cr)) echo "<option value='{$c['cat_id']}'>{$c['cat_title']}</option>";
                            ?>
                        </select><br>
                        <label>Brand</label>
                        <select name="pro_brand" id="edit_pro_brand" class="form-control">
                            <?php 
                            $br = mysqli_query($conn, "SELECT * FROM brands");
                            while($b = mysqli_fetch_array($br)) echo "<option value='{$b['brand_id']}'>{$b['brand_title']}</option>";
                            ?>
                        </select><br>
                        <label>Product Image (Leave blank to keep current)</label>
                        <input type="file" name="pro_img">
                    </div>
                    <div class="modal-footer">
                        <button type="submit" name="edit_pro" class="btn btn-warning">Update Product</button>
                        <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <script>
    $(document).ready(function() {
        // Trigger Edit Modal and fill data
        $('.edit-product-btn').click(function() {
            var data = $(this).data('info');
            $('#edit_pro_id').val(data.product_id);
            $('#edit_pro_title').val(data.product_title);
            $('#edit_pro_price').val(data.product_price);
            $('#edit_pro_cat').val(data.product_cat);
            $('#edit_pro_brand').val(data.product_brand);
            $('#editProductModal').modal('show');
        });
    });
    </script>
</body>
</html>
