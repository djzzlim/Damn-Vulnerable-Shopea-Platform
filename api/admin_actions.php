<?php
include("../db.php");

function generateUniqueName($originalName) {
    $ext = pathinfo($originalName, PATHINFO_EXTENSION); 
    // md5(uniqid()) works on older PHP versions unlike random_bytes
    $randomString = md5(uniqid(rand(), true)); 
    return $randomString . "." . $ext;
}

// DELETE PRODUCT
if(isset($_GET['del_pro'])) {
    $id = mysqli_real_escape_string($conn, $_GET['del_pro']);
    
    $select_sql = "SELECT product_image FROM products WHERE product_id = $id";
    $select_query = mysqli_query($conn, $select_sql);
    
    if($select_query && mysqli_num_rows($select_query) > 0) {
        $row = mysqli_fetch_array($select_query);
        $image_name = $row['product_image'];
        $image_path = "../assets/images/" . $image_name;

        if (!empty($image_name) && file_exists($image_path)) {
            unlink($image_path); // This deletes the physical file
        }
    }

    mysqli_query($conn, "DELETE FROM products WHERE product_id = $id");
    
    header("location:../admin.php?msg=Product and image deleted");
    exit();
}

// DELETE CATEGORY
if(isset($_GET['del_cat'])) {
    $id = $_GET['del_cat'];
    mysqli_query($conn, "DELETE FROM categories WHERE cat_id = $id");
    header("location:../admin.php");
}

// ADD CATEGORY (Vulnerable to SQL Injection)
if(isset($_POST['add_cat'])) {
    $title = $_POST['cat_title'];
    $sql = "INSERT INTO categories (cat_title) VALUES ('$title')";
    mysqli_query($conn, $sql);
    header("location:../admin.php");
}

// ADD BRAND (Vulnerable to SQL Injection)
if(isset($_POST['add_brand'])) {
    $title = $_POST['brand_title'];
    $sql = "INSERT INTO brands (brand_title) VALUES ('$title')";
    mysqli_query($conn, $sql);
    header("location:../admin.php");
}

// ADD PRODUCT
if(isset($_POST['add_pro'])) {
    $title = mysqli_real_escape_string($conn, $_POST['pro_title']);
    $price = mysqli_real_escape_string($conn, $_POST['pro_price']);
    $cat   = mysqli_real_escape_string($conn, $_POST['pro_cat']);
    $brand = mysqli_real_escape_string($conn, $_POST['pro_brand']);
    
    $original_name = $_FILES['pro_img']['name'];
    $img_tmp  = $_FILES['pro_img']['tmp_name'];
    
    // Randomize Name
    $img_name = generateUniqueName($original_name);
    
    if (move_uploaded_file($img_tmp, "../assets/images/$img_name")) {
        $sql = "INSERT INTO products (product_cat, product_brand, product_title, product_price, product_image) 
                VALUES ('$cat', '$brand', '$title', '$price', '$img_name')";
        
        if(mysqli_query($conn, $sql)) {
            header("location:../admin.php?msg=Product Added Successfully");
        } else {
            die("Database Error: " . mysqli_error($conn));
        }
    } else {
        die("Error: Failed to upload image to ../assets/images/");
    }
}

// EDIT PRODUCT
if(isset($_POST['edit_pro'])) {
    $id    = mysqli_real_escape_string($conn, $_POST['update_id']);
    $title = mysqli_real_escape_string($conn, $_POST['pro_title']);
    $price = $_POST['pro_price'];
    $cat   = $_POST['pro_cat'];
    $brand = $_POST['pro_brand'];
    
    // Check if a new image was uploaded
    if(!empty($_FILES['pro_img']['name'])) {
        $original_name = $_FILES['pro_img']['name'];
        $img_tmp       = $_FILES['pro_img']['tmp_name'];
        $img_name      = generateUniqueName($original_name);

        // 1. Fetch the OLD image name before updating the database
        $old_img_query = mysqli_query($conn, "SELECT product_image FROM products WHERE product_id = '$id'");
        if ($old_img_query && mysqli_num_rows($old_img_query) > 0) {
            $old_img_row = mysqli_fetch_array($old_img_query);
            $old_image_path = "../assets/images/" . $old_img_row['product_image'];

            // 2. Delete the physical old file if it exists
            if (!empty($old_img_row['product_image']) && file_exists($old_image_path)) {
                unlink($old_image_path); // Physically removes the old file
            }
        }

        // 3. Move the new file and prepare the SQL with the new image name
        if(move_uploaded_file($img_tmp, "../assets/images/$img_name")) {
            $sql = "UPDATE products SET 
                    product_cat = '$cat', 
                    product_brand = '$brand', 
                    product_title = '$title', 
                    product_price = '$price', 
                    product_image = '$img_name' 
                    WHERE product_id = $id";
        } else {
            die("Error: Failed to upload new image.");
        }
    } else {
        // Update query without changing the current image
        $sql = "UPDATE products SET 
                product_cat = '$cat', 
                product_brand = '$brand', 
                product_title = '$title', 
                product_price = '$price' 
                WHERE product_id = $id";
    }
    
    if(mysqli_query($conn, $sql)) {
        header("location:../admin.php?msg=Product Updated Successfully");
    } else {
        echo "Error: " . mysqli_error($conn);
    }
}

// DELETE BRAND (Missing from your previous list)
if(isset($_GET['del_brand'])) {
    $id = $_GET['del_brand'];
    mysqli_query($conn, "DELETE FROM brands WHERE brand_id = $id");
    header("location:../admin.php");
}
?>
