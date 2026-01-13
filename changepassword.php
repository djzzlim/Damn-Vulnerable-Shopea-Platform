<?php
session_start();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Change Password - Shopea</title>
    <link rel="stylesheet" href="assets/css/bootstrap.min.css">
    <style>
        body { background-color: #f5f5f5; padding-top: 70px; font-family: "Helvetica Neue", Helvetica, Arial, sans-serif; }

        .success-msg { 
            background-color: #fcf8e3; 
            color: #8a6d3b; 
            border: 1px solid #faebcc; 
            padding: 15px; 
            margin-bottom: 20px; 
            border-radius: 4px; 
        }

        .panel-primary > .panel-heading { background-color: #337ab7; border-color: #337ab7; }
        .btn-success { background-color: #5cb85c; border-color: #4cae4c; padding: 10px 20px; font-size: 16px; }

        .form-group label { font-weight: bold; margin-bottom: 10px; }
        .validation-error { color: #a94442; font-size: 12px; margin-top: 5px; display: none; }
    </style>
</head>
<body>

<?php include("includes/menubar.php"); ?>

<div class="container">
    <div class="row">
        <div class="col-md-6 col-md-offset-3">

            <?php if (isset($_GET['status']) && $_GET['status'] == 'success'): ?>
                <div class="success-msg" id="successAlert">
                    <button type="button" class="close" data-dismiss="alert">&times;</button>
                    You have successfully updated your password!
                </div>
            <?php endif; ?>

            <div class="panel panel-primary">
                <div class="panel-heading">
                    <h3 class="panel-title">Change Password</h3>
                </div>
                <div class="panel-body" style="padding: 40px;">
                    <form id="changePwForm" action="api/chpwd.php" method="POST">

                        <div class="form-group">
                            <label for="password">New Password</label>
                            <input type="password" name="password" id="password" class="form-control" required>
                            <div id="pw-hint" class="validation-error">Password must be at least 8 characters, include a letter and a number.</div>
                        </div>

                        <div class="form-group">
                            <label for="re_password">Re-enter New Password</label>
                            <input type="password" name="re_password" id="re_password" class="form-control" required>
                            <div id="match-error" class="validation-error">Passwords do not match!</div>
                        </div>

                        <div class="form-group text-right" style="margin-top: 30px;">
                            <button type="submit" class="btn btn-success">Change Password</button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>
</div>

<script src="assets/js/jquery-3.1.1.js"></script>
<script src="assets/js/bootstrap.min.js"></script>

<script>
$(document).ready(function() {
    $('.close').click(function(){
        $(this).parent().fadeOut();
    });

    $('#changePwForm').on('submit', function(e) {
        var password = $('#password').val();
        var confirmPassword = $('#re_password').val();

        // Regex for strength: 8+ chars, at least one letter and one number
        var pwRegex = /^(?=.*[a-z])(?=.*\d).{8,}$/;
        var isValid = true;

        $('.validation-error').hide();

        // 1. Check strength
        if (!pwRegex.test(password)) {
            $('#pw-hint').show();
            isValid = false;
        }

        // 2. Check match
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
