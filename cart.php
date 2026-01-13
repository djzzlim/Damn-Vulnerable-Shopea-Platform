<?php
// PHP 5.3 Compatible Session Start
if (!isset($_SESSION)) {
    session_start();
}
include("db.php");

if (!isset($_SESSION["uid"])) {
    header("location:index.php");
    exit();
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>Shopea - Your Cart</title>
    <link rel="stylesheet" href="assets/css/bootstrap.min.css">
    <script src="assets/js/jquery-3.1.1.js"></script>
    <script src="assets/js/bootstrap.min.js"></script>
</head>
<body>
    <?php include('includes/menubar.php'); ?>

    <div class="container" style="margin-top: 50px;">
        <div class="row">
            <div class="col-md-12">
                <div class="panel panel-primary">
                    <div class="panel-heading">Cart Checkout</div>
                    <div class="panel-body">
                        <div class="row header" style="font-weight:bold; border-bottom: 2px solid #ddd; padding-bottom:10px;">
                            <div class="col-md-2">Action</div>
                            <div class="col-md-2">Product Image</div>
                            <div class="col-md-3">Product Name</div>
                            <div class="col-md-2">Quantity</div>
                            <div class="col-md-3">Price (Subtotal)</div>
                        </div>

                        <div id="cart_checkout">
                            <?php
                            $uid = $_SESSION['uid'];
                            $total_amount = 0;
                            $sql = "SELECT a.product_id, a.product_title, a.product_price, a.product_image, b.qty 
                                    FROM products a, cart b WHERE a.product_id = b.p_id AND b.user_id = '$uid'";
                            $query = mysqli_query($conn, $sql);
                            
                            while ($row = mysqli_fetch_array($query)) {
                                $pid = $row['product_id'];
                                $qty = $row['qty'];
                                $subtotal = $row['product_price'] * $qty;
                                $total_amount += $subtotal;
                                
                                echo "
                                <div class='row' style='margin-top:10px; border-bottom:1px solid #eee; padding-bottom:10px; display: flex; align-items: center;'>
                                    <div class='col-md-2'>
                                        <a href='#' class='btn btn-danger remove' pid='$pid'><span class='glyphicon glyphicon-trash'></span></a>
                                    </div>
                                    <div class='col-md-2'><img src='assets/images/".$row['product_image']."' width='60px'></div>
                                    <div class='col-md-3'>".$row['product_title']."</div>
                                    <div class='col-md-2'>
                                        <input type='number' class='form-control qty-input' pid='$pid' value='$qty' min='1'>
                                    </div>
                                    <div class='col-md-3'>
                                        <span class='price'>$".number_format($row['product_price'], 2)."</span>
                                        <span class='pull-right'><strong>$".number_format($subtotal, 2)."</strong></span>
                                    </div>
                                </div>";
                            }
                            ?>
                        </div>

                        <div class="row" style="margin-top: 20px;">
                            <div class="col-md-7"></div>
                            <div class="col-md-5 text-right">
                                <div style="font-size: 20px; border-top: 2px solid #337ab7; padding-top: 10px; margin-bottom: 20px;">
                                    <strong>Total Amount: </strong>
                                    <span style="color: #337ab7;">$<?php echo number_format($total_amount, 2); ?></span>
                                </div>

                                <form action="https://www.sandbox.paypal.com/cgi-bin/webscr" method="post">
                                    <input type="hidden" name="business" value="test@gmail.com">
                                    <input type="hidden" name="cmd" value="_cart">
                                    <input type="hidden" name="upload" value="1">
                                    <input type="hidden" name="currency_code" value="USD">
                                    
                                    <?php
                                    // Reset pointer to loop through cart items for the form fields
                                    mysqli_data_seek($query, 0);
                                    $i = 1;
                                    while($item = mysqli_fetch_array($query)) {
                                        // VULNERABILITY: These values are sent directly from the client
                                        echo '<input type="hidden" name="item_name_'.$i.'" value="'.$item['product_title'].'">';
                                        echo '<input type="hidden" name="item_number_'.$i.'" value="'.$item['product_id'].'">';
                                        echo '<input type="hidden" name="amount_'.$i.'" value="'.$item['product_price'].'">';
                                        echo '<input type="hidden" name="quantity_'.$i.'" value="'.$item['qty'].'">';
                                        $i++;
                                    }
                                    ?>

                                    <input type="hidden" name="return" value="http://localhost/success.php">
                                    <input type="hidden" name="cancel_return" value="http://localhost/cart.php">
                                    
                                    <button type="submit" class="btn btn-success btn-lg btn-block">
                                        <span class="glyphicon glyphicon-shopping-cart"></span> Checkout
                                    </button>
                                </form>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
    $(document).ready(function() {
        // Auto-update quantity
        $('body').delegate('.qty-input', 'change', function() {
            var pid = $(this).attr('pid');
            var qty = $(this).val();
            if (qty < 1) { $(this).val(1); return; }

            $.ajax({
                url: "api/cart_action.php",
                method: "POST",
                data: { updateItem: 1, update_id: pid, qty: qty },
                success: function() { location.reload(); }
            });
        });

        // Remove item
        $('body').delegate('.remove', 'click', function(e) {
            e.preventDefault();
            var pid = $(this).attr('pid');
            if(confirm("Remove this item?")) {
                $.ajax({
                    url: "api/cart_action.php",
                    method: "POST",
                    data: { removeItem: 1, remove_id: pid },
                    success: function() { location.reload(); }
                });
            }
        });
    });
    </script>
</body>
</html>
