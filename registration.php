<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Customer Signup - Shopea</title>
    <link rel="stylesheet" href="assets/css/bootstrap.min.css">
    <style>
        body { background-color: #f5f5f5; padding-top: 50px; font-family: "Helvetica Neue", Helvetica, Arial, sans-serif; }
        .panel-primary > .panel-heading { background-color: #337ab7; border-color: #337ab7; }
        .success-msg { background-color: #fcf8e3; color: #8a6d3b; border: 1px solid #faebcc; padding: 10px 15px; margin-bottom: 20px; border-radius: 4px; position: relative; }
        .error-msg { background-color: #f2dede; color: #a94442; border: 1px solid #ebccd1; padding: 10px 15px; margin-bottom: 20px; border-radius: 4px; position: relative; }
        .btn-success { background-color: #5cb85c; border-color: #4cae4c; }
        .form-control { border-radius: 4px; box-shadow: inset 0 1px 1px rgba(0,0,0,.075); }
        .validation-error { color: #a94442; font-size: 12px; margin-top: 5px; display: none; }
    </style>
</head>
<body>

<?php include("includes/menubar.php"); ?>

<div class="container">
    <div class="row">
        <div class="col-md-6 col-md-offset-3">
            
            <?php
            if (isset($_GET['status'])) {
                if ($_GET['status'] == 'success') {
                    echo '<div class="success-msg"><button type="button" class="close" data-dismiss="alert">&times;</button>You have successfully registered with us, Thank you!</div>';
		} elseif ($_GET['status'] == 'email_exists') {
	            echo '<div class="error-msg"><button type="button" class="close" data-dismiss="alert">&times;</button>This email address already exists!</div>';
                } elseif ($_GET['status'] == 'fail') {
                    echo '<div class="error-msg"><button type="button" class="close" data-dismiss="alert">&times;</button>Registration failed. Please try again.</div>';
                }
            }
            ?>

            <div class="panel panel-primary">
                <div class="panel-heading">
                    <h3 class="panel-title">Customer Signup Form</h3>
                </div>
                <div class="panel-body">
                    <form id="regForm" action="api/register.php" method="POST">
                        <div class="row">
                            <div class="col-md-6 form-group">
                                <label>First Name</label>
                                <input type="text" name="first_name" class="form-control" required>
                            </div>
                            <div class="col-md-6 form-group">
                                <label>Last Name</label>
                                <input type="text" name="last_name" class="form-control" required>
                            </div>
                        </div>

                        <div class="form-group">
                            <label>Email</label>
                            <input type="email" name="email" class="form-control" required>
                        </div>

                        <div class="form-group">
                            <label>Password</label>
                            <input type="password" id="password" name="password" class="form-control" required>
			    <div id="pw-hint" class="validation-error">Password too weak.</div>
                        </div>

                        <div class="form-group">
                            <label>Re-enter Password</label>
                            <input type="password" id="re_password" name="re_password" class="form-control" required>
                            <div id="match-error" class="validation-error">Passwords do not match!</div>
                        </div>

                        <div class="form-group">
                            <label>Mobile</label>
                            <input type="text" name="mobile" class="form-control" required>
                        </div>

                        <div class="form-group">
                            <label>Address Line 1</label>
                            <input type="text" name="address1" class="form-control" required>
                        </div>

                        <div class="form-group">
                            <label>Address Line 2</label>
                            <input type="text" name="address2" class="form-control" required>
                        </div>

                        <div class="form-group text-right">
                            <button type="submit" class="btn btn-success">Signup</button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>
</div>

<script src="/assets/js/jquery-3.1.1.js"></script>
<script src="assets/js/bootstrap.min.js"></script>

<script>
$(document).ready(function() {

    $('.close').click(function(){
        $(this).parent().fadeOut();
    });

    $('#regForm').on('submit', function(e) {
        var password = $('#password').val();
        var confirmPassword = $('#re_password').val();
        
        // Regex: At least 8 chars, 1 lowercase letter, 1 number
        var pwRegex = /^(?=.*[a-z])(?=.*\d).{8,}$/;
        var isValid = true;

        // Reset errors
        $('.validation-error').hide();

        // Check Regex
        if (!pwRegex.test(password)) {
	    $('#pw-hint').show();
            isValid = false;
        }

        // Check Match
        if (password !== confirmPassword) {
            $('#match-error').show();
            isValid = false;
        }

        if (!isValid) {
            e.preventDefault();
        }
    });
});
</script>

</body>
</html>
