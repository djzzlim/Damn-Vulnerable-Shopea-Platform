<?php 
if (!isset($_SESSION)) {
    session_start(); 
}
include_once("db.php");

$cart_count = 0;
if (isset($_SESSION['uid'])) {
    $uid = $_SESSION['uid'];
    $sql = "SELECT SUM(qty) AS total_items FROM cart WHERE user_id = '$uid'";
    $query = mysqli_query($conn, $sql);

    if ($query) {
        $row = mysqli_fetch_array($query);
        $cart_count = ($row['total_items'] > 0) ? $row['total_items'] : 0;
    }
}
?>
<style>
    /* username: admin@technovation.local
       password: Abcd1234 */

    body { padding-top: 75px !important; }
    .login-box { width: 300px; padding: 15px; background-color: #337ab7; color: white; border: none; border-radius: 4px; }
    .login-box label { color: white; font-weight: bold; }
    .btn-login { background-color: #5cb85c; border-color: #4cae4c; color: white; }
    .login-footer { background-color: #f5f5f5; color: #333; margin: 15px -15px -15px -15px; padding: 10px; border-bottom-left-radius: 4px; border-bottom-right-radius: 4px; font-size: 13px; position: relative; }
    .forgot-pw { color: white; text-decoration: none; font-size: 12px; }
    .dropdown .caret { transition: transform 0.3s ease-in-out; }
    .dropdown.open .caret { transform: rotate(180deg); }
    .navbar-form .form-control { width: 300px !important; }
</style>

<nav class="navbar navbar-inverse navbar-fixed-top">
  <div class="container-fluid">
    <div class="navbar-header">
      <button type="button" class="navbar-toggle collapsed" data-toggle="collapse" data-target="#main-nav">
        <span class="icon-bar"></span>
        <span class="icon-bar"></span>
        <span class="icon-bar"></span>
      </button>
      <a class="navbar-brand" href="index.php">Shopea Online</a>
    </div>

    <div class="collapse navbar-collapse" id="main-nav">
      <ul class="nav navbar-nav">
        <li class="active"><a href="index.php"><span class="glyphicon glyphicon-home"></span> Home</a></li>
      </ul>

      <form class="navbar-form navbar-left" action="index.php" method="get">
        <div class="form-group">
          <input type="text" name="search" class="form-control" placeholder="Search for Products...">
        </div>
        <button type="submit" class="btn btn-primary">Search</button>
      </form>

      <ul class="nav navbar-nav navbar-right">
        <?php if (isset($_SESSION['uid'])): ?>
        <li>
            <a href="cart.php">
                <span class="glyphicon glyphicon-shopping-cart"></span> Cart 
                <span class="badge cart-badge"><?php echo ($cart_count > 0) ? $cart_count : '0'; ?></span>
            </a>
        </li>

        <li class="dropdown">
            <a href="#" class="dropdown-toggle" data-toggle="dropdown">
                <span class="glyphicon glyphicon-user"></span> 
                Welcome <?php echo $_SESSION['user_name']; ?> 
                <span class="caret"></span>
            </a>
            <ul class="dropdown-menu">
                <li><a href="changepassword.php"><span class="glyphicon glyphicon-lock"></span> Change Password</a></li>
                <li class="divider"></li>
                <li><a href="api/logout.php"><span class="glyphicon glyphicon-log-out"></span> Logout</a></li>
            </ul>
        </li>

        <?php else: ?>
            <li class="dropdown <?php echo (isset($_SESSION['error_msg'])) ? 'open' : ''; ?>">
              <a href="#" class="dropdown-toggle" data-toggle="dropdown">
                <span class="glyphicon glyphicon-user"></span> SignIn <span class="caret"></span>
              </a>
              <ul class="dropdown-menu login-box">
                <li>
                    <form action="api/login.php" method="POST">
                        <p style="font-size: 16px; margin-bottom: 15px;">Login</p>
                        <div class="form-group">
                            <label>Email</label>
                            <input type="email" name="email" class="form-control" required>
                        </div>
                        <div class="form-group">
                            <label>Password</label>
                            <input type="password" name="password" class="form-control" required>
                        </div>
                        <div class="row">
                            <div class="col-xs-7"><a href="#" class="forgot-pw">Forgot Password</a></div>
                            <div class="col-xs-5 text-right"><button type="submit" class="btn btn-login btn-sm">Login</button></div>
                        </div>
                        <?php if (isset($_SESSION['error_msg'])): ?>
                        <div class="login-footer" id="invalidLoginBox">
                            <button type="button" class="close" style="font-size: 14px; margin-top: -2px;">&times;</button>
                            <?php 
                                echo $_SESSION['error_msg'];
                                unset($_SESSION['error_msg']);
                            ?>
                        </div>
                        <?php endif; ?>
                    </form>
                </li>
              </ul>
            </li>
            <li><a href="registration.php"><span class="glyphicon glyphicon-user"></span> SignUp</a></li>
        <?php endif; ?>
      </ul>
    </div>
  </div>
</nav>
