# app.py
# ---------------------------------------------------------
# DAY 2: Admin Signup + OTP + Password Hash
# ---------------------------------------------------------

from flask import Flask, make_response, render_template, request, redirect, session, flash, jsonify, url_for
from flask_mail import Mail, Message
from flask_bcrypt import Bcrypt
import mysql.connector
import random
import config
import os
from werkzeug.utils import secure_filename
import webbrowser
import traceback
import razorpay

from utils.pdf_generator import generate_pdf


app = Flask(__name__)
app.secret_key = config.SECRET_KEY

bcrypt = Bcrypt(app)

razorpay_client = razorpay.Client(
    auth=(config.RAZORPAY_KEY_ID, config.RAZORPAY_KEY_SECRET)
)

# ---------------- EMAIL CONFIGURATION ----------------
app.config['MAIL_SERVER'] = config.MAIL_SERVER
app.config['MAIL_PORT'] = config.MAIL_PORT
app.config['MAIL_USE_TLS'] = config.MAIL_USE_TLS
app.config['MAIL_USERNAME'] = config.MAIL_USERNAME
app.config['MAIL_PASSWORD'] = config.MAIL_PASSWORD

mail = Mail(app)


# ---------------- DB CONNECTION FUNCTION --------------
def get_db_connection():
    return mysql.connector.connect(
        host=config.DB_HOST,
        user=config.DB_USER,
        password=config.DB_PASSWORD,
        database=config.DB_NAME
    )


# ---------------------------------------------------------
# ROUTE 1: ADMIN SIGNUP (SEND OTP)
# ---------------------------------------------------------
@app.route('/admin-signup', methods=['GET', 'POST'])
def admin_signup():

    if request.method == "GET":
        return render_template("admin/admin_signup.html")

    name = request.form['name']
    email = request.form['email']
   
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT admin_id FROM admin WHERE email=%s", (email,))
    existing_admin = cursor.fetchone()

    cursor.close()
    conn.close()

    if existing_admin:
        flash("This email is already registered. Please login instead.", "danger")
        return redirect('/admin-signup')

    session['signup_name'] = name
    session['signup_email'] = email
   
    otp = random.randint(100000, 999999)
    session['otp'] = otp

    message = Message(
        subject="SmartCart Admin OTP",
        sender=app.config['MAIL_USERNAME'],
        recipients=[email]
    )
    message.body = f"Your OTP for SmartCart Admin Registration is: {otp}"
    mail.send(message)

    flash("OTP sent to your email!", "success")
    return redirect('/verify-otp')



# ---------------------------------------------------------
# ROUTE 2: DISPLAY OTP PAGE
# ---------------------------------------------------------
@app.route('/verify-otp', methods=['GET'])
def verify_otp_get():
    return render_template("admin/verify_otp.html")



# ============================================================
# VERIFY OTP + SAVE ADMIN + SEND APPROVAL MAIL
# ============================================================
@app.route('/verify-otp', methods=['POST'])
def verify_otp_post():

    user_otp = request.form['otp']
    password = request.form['password']

    if str(session.get('otp')) != str(user_otp):
        flash("Invalid OTP. Try again!", "danger")
        return redirect('/verify-otp')

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        INSERT INTO admin (name, email, password, status)
        VALUES (%s, %s, %s, %s)
    """, (
        session['signup_name'],
        session['signup_email'],
        hashed_password,
        'pending'
    ))

    conn.commit()
    admin_id = cursor.lastrowid

    cursor.close()
    conn.close()

    approve_link = url_for('approve_admin', admin_id=admin_id, _external=True)
    reject_link = url_for('reject_admin', admin_id=admin_id, _external=True)

    message = Message(
        subject="New Admin Approval Request",
        sender=app.config['MAIL_USERNAME'],
        recipients=[app.config['MAIL_USERNAME']]
    )

    message.body = f"""
New admin registered and is waiting for approval.

Name: {session['signup_name']}
Email: {session['signup_email']}

Approve Admin:
{approve_link}

Reject Admin:
{reject_link}
"""

    mail.send(message)

    session.pop('otp', None)
    session.pop('signup_name', None)
    session.pop('signup_email', None)

    flash("Registration successful! Please wait for Super Admin approval.", "info")
    return redirect('/admin-login')

#==================================================================
# ROUTE 4: ADMIN LOGIN PAGE (GET + POST)
# =================================================================
@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():

    if request.method == 'GET':
        return render_template("admin/admin_login.html")

    email = request.form['email']
    password = request.form['password']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM admin WHERE email=%s", (email,))
    admin = cursor.fetchone()

    cursor.close()
    conn.close()

    if admin is None:
        flash("Email not found! Please register first.", "danger")
        return redirect('/admin-login')

    # ✅ Block pending/rejected admins
    if admin['status'] != 'approved':
        flash("Your admin account is not approved by Super Admin!", "warning")
        return redirect('/admin-login')

    # ✅ Flask-Bcrypt password check
    if not bcrypt.check_password_hash(admin['password'], password):
        flash("Incorrect password! Try again.", "danger")
        return redirect('/admin-login')

    session['admin_id'] = admin['admin_id']
    session['admin_name'] = admin['name']
    session['admin_email'] = admin['email']

    flash("Login Successful!", "success")
    return redirect('/admin-dashboard')


#==================================================================
#================================================================== 
#==================================================================
#==================================================================

@app.route('/')
def home():
    return redirect('/superadmin-login')

#===================================================================
#===================================================================
#===================================================================



# =================================================================
# ROUTE 5: ADMIN DASHBOARD (PROTECTED ROUTE)
# =================================================================
@app.route('/admin-dashboard')
def admin_dashboard():

    if 'admin_id' not in session:
        flash("Please login to access dashboard!", "danger")
        return redirect('/admin-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT COUNT(*)
        FROM products
        WHERE admin_id = %s
    """, (session['admin_id'],))

    total_products = cursor.fetchone()[0]

    cursor.close()
    conn.close()

    print("TOTAL PRODUCTS:", total_products)

    return render_template(
        "admin/dashboard.html",
        admin_name=session['admin_name'],
        total_products=total_products
    )


# =================================================================
# ROUTE 6: ADMIN LOGOUT
# =================================================================
@app.route('/admin-logout')
def admin_logout():

    # Clear admin session
    session.pop('admin_id', None)
    session.pop('admin_name', None)
    session.pop('admin_email', None)

    flash("Logged out successfully.", "success")
    return redirect('/admin-login')




# ------------------- IMAGE UPLOAD PATH -------------------
UPLOAD_FOLDER = 'static/uploads/product_images'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


# =================================================================
# ROUTE 8: ADD PRODUCT INTO DATABASE
# =================================================================
@app.route('/admin/add-item', methods=['GET', 'POST'])
def add_item():

    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    if request.method == 'GET':
        return render_template("admin/add_item.html")

    name = request.form['name']
    description = request.form['description']
    category = request.form['category']
    price = request.form['price']
    image_file = request.files['image']

    if image_file.filename == "":
        flash("Please upload a product image!", "danger")
        return redirect('/admin/add-item')

    filename = secure_filename(image_file.filename)

    image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    image_file.save(image_path)

    admin_id = session['admin_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO products (admin_id, name, description, category, price, image)
        VALUES (%s, %s, %s, %s, %s, %s)
    """, (admin_id, name, description, category, price, filename))

    conn.commit()
    cursor.close()
    conn.close()

    flash("Product added successfully!", "success")
    return redirect('/admin/item-list')
# =================================================================
# ROUTE 9: DISPLAY ALL PRODUCTS (Admin)
# =================================================================
@app.route('/admin/item-list')
def item_list():

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    search = request.args.get('search', '')
    category_filter = request.args.get('category', '')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # ✅ Fetch categories only for this admin
    cursor.execute("""
        SELECT DISTINCT category 
        FROM products 
        WHERE admin_id = %s
    """, (session['admin_id'],))
    categories = cursor.fetchall()

    # ✅ Base query with admin filter
    query = "SELECT * FROM products WHERE admin_id = %s"
    params = [session['admin_id']]

    if search:
        query += " AND name LIKE %s"
        params.append("%" + search + "%")

    if category_filter:
        query += " AND category = %s"
        params.append(category_filter)

    query += " ORDER BY product_id DESC"

    cursor.execute(query, params)
    products = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        "admin/item_list.html",
        products=products,
        categories=categories
    )



# =================================================================
# ROUTE 10: VIEW SINGLE PRODUCT DETAILS
# =================================================================
@app.route('/admin/view-item/<int:item_id>')
def view_item(item_id):

    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT *
        FROM products
        WHERE product_id = %s AND admin_id = %s
    """, (item_id, session['admin_id']))

    product = cursor.fetchone()

    cursor.close()
    conn.close()

    if not product:
        flash("Product not found or access denied!", "danger")
        return redirect('/admin/item-list')

    return render_template("admin/view_item.html", product=product)


# =================================================================
# ROUTE 11: SHOW UPDATE FORM WITH EXISTING DATA
# =================================================================
@app.route('/admin/update-item/<int:item_id>', methods=['GET'])
def update_item_page(item_id):

    # Check login
    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    # Fetch product data
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM products WHERE product_id = %s", (item_id,))
    product = cursor.fetchone()

    cursor.close()
    conn.close()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/admin/item-list')

    return render_template("admin/update_item.html", product=product)


# =================================================================
# ROUTE-12: UPDATE PRODUCT + OPTIONAL IMAGE REPLACE
# =================================================================
@app.route('/admin/update-item/<int:item_id>', methods=['POST'])
def update_item(item_id):

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    # 1️⃣ Get updated form data
    name = request.form['name']
    description = request.form['description']
    category = request.form['category']
    price = request.form['price']

    new_image = request.files['image']

    # 2️⃣ Fetch old product data
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM products WHERE product_id = %s", (item_id,))
    product = cursor.fetchone()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/admin/item-list')

    old_image_name = product['image']

    # 3️⃣ If admin uploaded a new image → replace it
    if new_image and new_image.filename != "":
        
        # Secure filename
        from werkzeug.utils import secure_filename
        new_filename = secure_filename(new_image.filename)

        # Save new image
        new_image_path = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)
        new_image.save(new_image_path)

        # Delete old image file
        old_image_path = os.path.join(app.config['UPLOAD_FOLDER'], old_image_name)
        if os.path.exists(old_image_path):
            os.remove(old_image_path)

        final_image_name = new_filename

    else:
        # No new image uploaded → keep old one
        final_image_name = old_image_name

    # 4️⃣ Update product in the database
    cursor.execute("""
        UPDATE products
        SET name=%s, description=%s, category=%s, price=%s, image=%s
        WHERE product_id=%s
    """, (name, description, category, price, final_image_name, item_id))

    conn.commit()
    cursor.close()
    conn.close()

    flash("Product updated successfully!", "success")
    return redirect('/admin/item-list')


# =================================================================
# ROUTE 13: DELETE PRODUCT
# =================================================================
@app.route('/admin/delete-item/<int:item_id>')
def delete_item(item_id):

    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # 1️⃣ Fetch product to get image name
    cursor.execute("SELECT image FROM products WHERE product_id=%s", (item_id,))
    product = cursor.fetchone()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/admin/item-list')

    image_name = product['image']

    # Delete image from folder
    image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_name)
    if os.path.exists(image_path):
        os.remove(image_path)

    # 2️⃣ Delete product from DB
    cursor.execute("DELETE FROM products WHERE product_id=%s", (item_id,))
    conn.commit()

    cursor.close()
    conn.close()

    flash("Product deleted successfully!", "success")
    return redirect('/admin/item-list')

ADMIN_UPLOAD_FOLDER = 'static/uploads/admin_profiles'
app.config['ADMIN_UPLOAD_FOLDER'] = ADMIN_UPLOAD_FOLDER



# =================================================================
# ROUTE 14: SHOW ADMIN PROFILE DATA
# =================================================================
@app.route('/admin/profile', methods=['GET'])
def admin_profile():

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM admin WHERE admin_id = %s", (admin_id,))
    admin = cursor.fetchone()

    cursor.close()
    conn.close()

    return render_template("admin/admin_profile.html", admin=admin)


# =================================================================
# ROUTE 2: UPDATE ADMIN PROFILE (NAME, EMAIL, PASSWORD, IMAGE)
# =================================================================
@app.route('/admin/profile', methods=['POST'])
def admin_profile_update():

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    # 1️⃣ Get form data
    name = request.form['name']
    email = request.form['email']
    new_password = request.form['password']
    new_image = request.files['profile_image']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # 2️⃣ Fetch old admin data
    cursor.execute("SELECT * FROM admin WHERE admin_id = %s", (admin_id,))
    admin = cursor.fetchone()

    old_image_name = admin['profile_image']

    # 3️⃣ Update password only if entered
    if new_password:
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
    else:
        hashed_password = admin['password']  # keep old password

    # 4️⃣ Process new profile image if uploaded
    if new_image and new_image.filename != "":
        
        from werkzeug.utils import secure_filename
        new_filename = secure_filename(new_image.filename)

        # Save new image
        image_path = os.path.join(app.config['ADMIN_UPLOAD_FOLDER'], new_filename)
        new_image.save(image_path)

        # Delete old image
        if old_image_name:
            old_image_path = os.path.join(app.config['ADMIN_UPLOAD_FOLDER'], old_image_name)
            if os.path.exists(old_image_path):
                os.remove(old_image_path)

        final_image_name = new_filename
    else:
        final_image_name = old_image_name

    # 5️⃣ Update database
    cursor.execute("""
        UPDATE admin
        SET name=%s, email=%s, password=%s, profile_image=%s
        WHERE admin_id=%s
    """, (name, email, hashed_password, final_image_name, admin_id))

    conn.commit()
    cursor.close()
    conn.close()

    # Update session name for UI consistency
    session['admin_name'] = name  
    session['admin_email'] = email

    flash("Profile updated successfully!", "success")
    return redirect('/admin/profile')



#================================================================

#ROUTE: CONTACT ROUTE (GET + POST METHODS)

#================================================================

from flask import request, redirect, url_for, flash, render_template
from flask_mail import Message

@app.route('/admin-contact', methods=['GET', 'POST'])
def admin_contact():

    if request.method == 'POST':

        name = request.form.get('name')
        phone = request.form.get('phone')
        email = request.form.get('email')
        message_text = request.form.get('message')

        try:
            msg = Message(
                subject="New Contact Message - SmartCart",
                sender=app.config['MAIL_USERNAME'],
                recipients=[app.config['MAIL_USERNAME']]
            )

            msg.body = f"""
New Contact Message:

Name: {name}
Phone: {phone}
Email: {email}

Message:
{message_text}
"""

            mail.send(msg)

            flash("Message sent successfully!", "success")

        except Exception as e:
            print(e)  # helps debugging
            flash("Error sending message. Try again!", "danger")

        return redirect(url_for('admin_contact'))  # ✅ better than hardcoding

    return render_template('admin/contact.html')

#=================================================================
#ABOUT FOR THE LOGIN DIRECTLY
#=================================================================

@app.route('/about')
def about():
    return render_template('admin/about.html')

import webbrowser




#===================================================================
#FORGOT ROUTE 
#FOR FORGOT CREDDENTIALS

#===================================================================

@app.route('/forgot-password', methods=['GET','POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # ✅ check if email exists
        cursor.execute("SELECT * FROM admin WHERE email=%s", (email,))
        admin = cursor.fetchone()

        cursor.close()
        conn.close()

        if admin:
            # 🔥 generate OTP
            otp = random.randint(100000, 999999)

            # store in session
            session['forgot_otp'] = otp
            session['reset_email'] = email

            # 🔥 send email
            msg = Message(
                subject="SmartCart Password Reset OTP",
                sender=app.config['MAIL_USERNAME'],
                recipients=[email]
            )
            msg.body = f"Your OTP for password reset is: {otp}"

            mail.send(msg)

            flash("OTP sent to your email!", "success")
            return redirect('/verify-otp')

        else:
            flash("Email not found!", "danger")

    return render_template('admin/forgot.html')



#====================================================================
#VERIFY OTP FOR FOGOT PAGE
#FOR VERIFYING OTP
#====================================================================
@app.route('/verify-otp', methods=['GET','POST'])
def verify_otp():
    if request.method == 'POST':
        user_otp = request.form['otp']

        if str(user_otp) == str(session.get('forgot_otp')):
            flash("OTP verified!", "success")
            return redirect('/reset-password')
        else:
            flash("Invalid OTP!", "danger")

    return render_template('admin/verify.html')



#====================================================================
#RESET PASSWORD ROUTE
#====================================================================


@app.route('/reset-password', methods=['GET','POST'])
def reset_password():
    if request.method == 'POST':
        password = request.form['password']
        confirm = request.form['confirm_password']

        if password == confirm:

            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

            conn = get_db_connection()
            cursor = conn.cursor()

            cursor.execute(
                "UPDATE admin SET password=%s WHERE email=%s",
                (hashed_password, session.get('reset_email'))
            )

            conn.commit()
            cursor.close()
            conn.close()

            # clear session
            session.pop('forgot_otp', None)
            session.pop('reset_email', None)

            flash("Password updated successfully!", "success")
            return redirect('/admin-login')

        else:
            flash("Passwords do not match!", "danger")

    return render_template('admin/reset.html')



#==================================================================
#==================================================================
#==================================================================
#==================================================================
#==================================================================
#==================================================================
#==================================================================
#==================================================================
#==================================================================
#==================================================================
#==================================================================
#==================================================================
#==================================================================


#==================================================================
# ROUTE 1: User Registration (GET + POST)
# =================================================================
# ROUTE: USER REGISTRATION
# =================================================================
@app.route('/user-register', methods=['GET', 'POST'])
def user_register_page():

    if request.method == 'GET':
        return render_template("user/user_register.html")

    name = request.form.get('name')
    email = request.form.get('email')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
    existing_user = cursor.fetchone()

    cursor.close()
    conn.close()

    if existing_user:
        flash("Email already registered!", "danger")
        return redirect('/user-register')

    # ✅ store in session
    session['reg_name'] = name
    session['reg_email'] = email

    # ✅ generate OTP
    otp = random.randint(100000, 999999)
    session['reg_otp'] = otp

    # ✅ send mail
    msg = Message(
        subject="User Registration OTP",
        sender=app.config['MAIL_USERNAME'],
        recipients=[email]
    )
    msg.body = f"Your OTP is: {otp}"
    mail.send(msg)

    flash("OTP sent to your email!", "success")
    return redirect('/user-register-otp')
#==================================================================
# ROUTE 2: User Login (GET + POST)
# =================================================================
# ROUTE: USER LOGIN
# =================================================================
@app.route('/user-login', methods=['GET', 'POST'])
def user_login():

    if request.method == 'GET':
        return render_template("user/user_login.html")

    email = request.form['email']
    password = request.form['password']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
    user = cursor.fetchone()

    cursor.close()
    conn.close()

    if not user:
        flash("Email not found! Please register.", "danger")
        return redirect('/user-login')

    # ✅ FIXED LINE
    if not bcrypt.check_password_hash(user['password'], password):
        flash("Incorrect password!", "danger")
        return redirect('/user-login')

    # Create user session
    session['user_id'] = user['user_id']
    session['user_name'] = user['name']
    session['user_email'] = user['email']

    flash("Login successful!", "success")
    return redirect('/user-dashboard')
#==================================================================
# ROUTE 3: User Dashboard (Protected)
# =================================================================
# ROUTE: USER DASHBOARD
# =================================================================
@app.route('/user-dashboard')
def user_dashboard():

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    # 🔥 GET PRODUCTS
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM products LIMIT 8")
    products = cursor.fetchall()

    conn.close()

    return render_template(
        "user/user_home.html",
        user_name=session['user_name'],
        products=products   # 🔥 SEND TO HTML
    )

#==================================================================
# ROUTE 4: User Logout
# =================================================================
# ROUTE: USER LOGOUT
# =================================================================
@app.route('/user-logout')
def user_logout():
    
    session.pop('user_id', None)
    session.pop('user_name', None)
    session.pop('user_email', None)

    flash("Logged out successfully!", "success")
    return redirect('/user-login')


#==================================================================
#----5---ABOUT PAGE ROUTE FOR USER
#==================================================================
@app.route('/user-about')
def user_about():
    return render_template('user/about.html')


# ROUTE 6: Display All Products for Users
# =================================================================
# ROUTE: USER PRODUCT LISTING (SEARCH + FILTER)
# =================================================================
@app.route('/user/products')
def user_products():

    # Optional: restrict only logged-in users
    if 'user_id' not in session:
        flash("Please login to view products!", "danger")
        return redirect('/user-login')

    search = request.args.get('search', '')
    category_filter = request.args.get('category', '')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Fetch categories for filter dropdown
    cursor.execute("SELECT DISTINCT category FROM products")
    categories = cursor.fetchall()

    # Build dynamic SQL
    query = "SELECT * FROM products WHERE 1=1"
    params = []

    if search:
        query += " AND name LIKE %s"
        params.append("%" + search + "%")

    if category_filter:
        query += " AND category = %s"
        params.append(category_filter)

    cursor.execute(query, params)
    products = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        "user/user_products.html",
        products=products,
        categories=categories
    )

# ROUTE 7: Single Product Details Page
# =================================================================
# ROUTE: USER PRODUCT DETAILS PAGE
# =================================================================
@app.route('/user/product/<int:product_id>')
def user_product_details(product_id):

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM products WHERE product_id = %s", (product_id,))
    product = cursor.fetchone()

    cursor.close()
    conn.close()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/user/products')

    return render_template("user/product_details.html", product=product)


#=========================================================================
#8--CONTACT ROUTE
#8--CONTACT ROUTE
#=========================================================================

@app.route('/user-contact', methods=['GET', 'POST'])
def user_contact():

    if request.method == 'POST':
        name = request.form['name']
        phone = request.form['phone']
        email = request.form['email']
        message_text = request.form['message']

        try:
            msg = Message(
                subject="User Contact Message - SmartCart",
                sender=app.config['MAIL_USERNAME'],
                recipients=[app.config['MAIL_USERNAME']]
            )

            msg.body = f"""
Name: {name}
Phone: {phone}
Email: {email}

Message:
{message_text}
"""
            mail.send(msg)

            flash("Message sent successfully!", "success")

        except Exception as e:
            print(e)
            flash("Error sending message!", "danger")

        return redirect('/user-contact')

    return render_template('user/user_contact.html')


#=================================================================
#------9----OTP VERIFY + REGISTER ROUTE
#------9----OTP VERIFY + REGISTER ROUTE
#------9----OTP VERIFY + REGISTER ROUTE
#=================================================================
@app.route('/user-register-otp', methods=['GET', 'POST'])
def user_register_otp():

    if request.method == 'POST':
        user_otp = request.form['otp']
        password = request.form['password']

        if str(user_otp) != str(session.get('reg_otp')):
            flash("Invalid OTP!", "danger")
            return redirect('/user-register-otp')

        # ✅ hash password
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            "INSERT INTO users (name, email, password) VALUES (%s, %s, %s)",
            (session['reg_name'], session['reg_email'], hashed_password)
        )

        conn.commit()
        cursor.close()
        conn.close()

        # clear session
        session.pop('reg_name', None)
        session.pop('reg_email', None)
        session.pop('reg_otp', None)

        flash("Registration successful! Please login.", "success")
        return redirect('/user-login')

    return render_template("user/register_otp.html")



#ROUTE 10: Add to Cart
# =================================================================
# ADD ITEM TO CART
# =================================================================
@app.route('/user/add-to-cart/<int:product_id>', methods=['POST'])
def add_to_cart(product_id):

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    # Create cart if doesn't exist
    if 'cart' not in session:
        session['cart'] = {}

    cart = session['cart']

    # Get product
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM products WHERE product_id=%s", (product_id,))
    product = cursor.fetchone()
    cursor.close()
    conn.close()

    if not product:
        flash("Product not found!", "danger")
        return redirect(request.referrer)

    pid = str(product_id)

    # If exists → increase quantity
    if pid in cart:
        cart[pid]['quantity'] += 1
        flash("Quantity increased!", "success")   # 🔥 added
    else:
        cart[pid] = {
            'name': product['name'],
            'price': float(product['price']),
            'image': product['image'],
            'quantity': 1
        }
        flash("Item added to cart!", "success")   # 🔥 added

    session['cart'] = cart

    return redirect(request.referrer)
#ROUTE 11: View Cart Page
# =================================================================
# VIEW CART PAGE
# =================================================================
@app.route('/user/cart')
def view_cart():

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    # ✅ Show welcome only once
    if not session.get('cart_visited'):
        flash("Welcome to cart!", "info")
        session['cart_visited'] = True

    cart = session.get('cart', {})

    # Calculate total
    grand_total = sum(item['price'] * item['quantity'] for item in cart.values())

    return render_template("user/cart.html", cart=cart, grand_total=grand_total)

#ROUTE 12: Increase Quantity
# =================================================================
# INCREASE QUANTITY
# =================================================================
@app.route('/user/cart/increase/<pid>')
def increase_quantity(pid):

    cart = session.get('cart', {})

    if pid in cart:
        cart[pid]['quantity'] += 1

    session['cart'] = cart
    return redirect('/user/cart')


#ROUTE 13: Decrease Quantity
# =================================================================
# DECREASE QUANTITY
# =================================================================
@app.route('/user/cart/decrease/<pid>')
def decrease_quantity(pid):

    cart = session.get('cart', {})

    if pid in cart:
        cart[pid]['quantity'] -= 1

        # If quantity becomes 0 → remove item
        if cart[pid]['quantity'] <= 0:
            cart.pop(pid)

    session['cart'] = cart
    return redirect('/user/cart')

#ROUTE 14: Remove Item Completely
# =================================================================
# REMOVE ITEM
# =================================================================
@app.route('/user/cart/remove/<pid>')
def remove_from_cart(pid):

    cart = session.get('cart', {})

    if pid in cart:
        cart.pop(pid)

    session['cart'] = cart

    flash("Item removed!", "success")
    return redirect('/user/cart')

#====================================================================
#---15----USER PROFILE PAGE
#---15----USER PROFILE PAGE
#====================================================================

@app.route('/user/profile', methods=['GET', 'POST'])
def user_profile():
    if 'user_id' not in session:
        return redirect('/user-login')

    user_id = session['user_id']

    # ✅ DB connection fix
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # 🔹 GET
    if request.method == 'GET':
        cursor.execute("SELECT * FROM users WHERE user_id=%s", (user_id,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()
        return render_template('user/user_profile.html', user=user)

    # 🔹 POST
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        image = request.files['profile_image']

        if image and image.filename != "":
            from werkzeug.utils import secure_filename
            filename = secure_filename(image.filename)

            path = os.path.join('static/uploads/user_profiles', filename)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            image.save(path)

            cursor.execute(
                "UPDATE users SET name=%s, email=%s, profile_image=%s WHERE user_id=%s",
                (name, email, filename, user_id)
            )
        else:
            cursor.execute(
                "UPDATE users SET name=%s, email=%s WHERE user_id=%s",
                (name, email, user_id)
            )

        # ✅ bcrypt fix
        if password:
            hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            cursor.execute(
                "UPDATE users SET password=%s WHERE user_id=%s",
                (hashed, user_id)
            )

        # ✅ commit fix
        conn.commit()

        cursor.close()
        conn.close()

        flash("Profile updated successfully!", "success")
        return redirect('/user/profile')
    

# =========================================================
# ----16----USER FORGOT PASSWORD (SEND OTP)
# =========================================================
@app.route('/user-forgot-password', methods=['GET', 'POST'])
def user_forgot_password():

    if request.method == 'POST':
        email = request.form['email']

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()

        cursor.close()
        conn.close()

        if user:
            otp = random.randint(100000, 999999)

            session['user_reset_email'] = email
            session['user_reset_otp'] = otp

            msg = Message(
                subject="SmartCart Password Reset OTP",
                sender=app.config['MAIL_USERNAME'],
                recipients=[email]
            )
            msg.body = f"Your OTP is: {otp}"
            mail.send(msg)

            flash("OTP sent successfully!", "success")
            return redirect('/user-reset-password')

        else:
            flash("Email not found!", "danger")

    return render_template('user/user_forgot.html')


# =========================================================
# ----17----USER RESET PASSWORD (OTP + PASSWORD)
# =========================================================
@app.route('/user-reset-password', methods=['GET', 'POST'])
def user_reset_password():

    if request.method == 'POST':
        otp = request.form['otp']
        password = request.form['password']
        confirm = request.form['confirm_password']

        if str(otp) != str(session.get('user_reset_otp')):
            flash("Invalid OTP!", "danger")
            return redirect('/user-reset-password')

        if password != confirm:
            flash("Passwords do not match!", "danger")
            return redirect('/user-reset-password')

        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            "UPDATE users SET password=%s WHERE email=%s",
            (hashed, session.get('user_reset_email'))
        )

        conn.commit()
        cursor.close()
        conn.close()

        session.pop('user_reset_email', None)
        session.pop('user_reset_otp', None)

        flash("Password updated successfully!", "success")
        return redirect('/user-login')

    return render_template('user/user_reset.html')
# =========================
# --------18---------BUY SELECTED ITEMS
# =========================
@app.route('/user/buy-selected', methods=['POST'])
def buy_selected():
    selected_ids = request.form.getlist('selected_items')

    cart = session.get('cart', {})
    selected_items = []

    for pid in selected_ids:
        if pid in cart:
            item = cart[pid].copy()   # 🔥 safe copy

            item['id'] = pid          # 🔥 IMPORTANT LINE

            selected_items.append(item)

    session['selected_items'] = selected_items

    return redirect('/user/address')


# =========================
# ADDRESS PAGE
# =========================
@app.route('/user/address')
def address():
    if 'user_id' not in session:
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM addresses WHERE user_id=%s ORDER BY id DESC",
                   (session['user_id'],))
    addresses = cursor.fetchall()

    conn.close()

    return render_template('user/address.html', addresses=addresses)

#========================================================================================
@app.route('/user/edit-address/<int:id>', methods=['GET','POST'])
def edit_address(id):

    if 'user_id' not in session:
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # 👉 UPDATE LOGIC
    if request.method == 'POST':
        cursor.execute("""
        UPDATE addresses 
        SET full_name=%s, phone=%s, address=%s, city=%s, state=%s, pincode=%s
        WHERE id=%s AND user_id=%s
        """, (
            request.form['full_name'],
            request.form['phone'],
            request.form['address'],
            request.form['city'],
            request.form['state'],
            request.form['pincode'],
            id,
            session['user_id']
        ))

        conn.commit()
        conn.close()

        return redirect('/user/address')

    # 👉 FETCH ADDRESS
    cursor.execute("SELECT * FROM addresses WHERE id=%s AND user_id=%s",
                   (id, session['user_id']))
    address = cursor.fetchone()

    conn.close()

    return render_template('user/edit_address.html', address=address)
# =========================
# SAVE ADDRESS
# =========================
@app.route('/user/save-address', methods=['POST'])
def save_address():
    if 'user_id' not in session:
        return redirect('/user-login')

    data = request.form

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO addresses (user_id, full_name, phone, pincode, address, city, state)
        VALUES (%s,%s,%s,%s,%s,%s,%s)
    """, (
        session['user_id'],
        data.get('full_name'),
        data.get('phone'),
        data.get('pincode'),
        data.get('address'),
        data.get('city'),
        data.get('state')
    ))

    conn.commit()
    conn.close()

    return redirect('/user/address')


# =========================
# SELECT ADDRESS
# =========================

@app.route('/user/buy-now/<int:product_id>')
def buy_now(product_id):

    if 'user_id' not in session:
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM products WHERE product_id=%s", (product_id,))
    product = cursor.fetchone()

    conn.close()

    if not product:
        return redirect('/user/products')

    # ✅ store product in session
    session['buy_now'] = {
        "product_id": product['product_id'],
        "name": product['name'],
        "price": float(product['price']),
        "quantity": 1,
        "image": product['image']
    }

    return redirect('/user/address')
#============================================
@app.route('/user/select-address/<int:address_id>')
def select_address(address_id):
    if 'user_id' not in session:
        return redirect('/user-login')

    session['selected_address'] = address_id
    return redirect('/user/pay')


# =========================
# DELETE ADDRESS
# =========================
@app.route('/user/delete-address/<int:address_id>', methods=['POST'])
def delete_address(address_id):

    if 'user_id' not in session:
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        DELETE FROM addresses 
        WHERE id=%s AND user_id=%s
    """, (address_id, session['user_id']))

    conn.commit()
    conn.close()

    return redirect('/user/address')


# =========================
# EDIT PAGE
# =========================



# =========================
# UPDATE ADDRESS
# =========================

# =========================
# --------21---------CONFIRM ORDER PAGE
# =========================
@app.route('/user/confirm-order')
def confirm_order():
    selected_items = session.get('selected_items', [])
    address = session.get('address', '')

    grand_total = 0
    for item in selected_items:
        grand_total += float(item['price']) * float(item['quantity'])

    return render_template(
        'user/confirm_order.html',
        selected_items=selected_items,
        address=address,
        grand_total=grand_total
    )


# =========================
# --------22---------PLACE ORDER
# =========================
@app.route('/user/place-order')
def place_order():
    session.pop('selected_items', None)
    return "✅ Order Placed Successfully!"

# =================================================================
# ------23---------ROUTE: CREATE RAZORPAY ORDER
# =================================================================
@app.route('/user/pay')
def user_pay():

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    # 🔥 STEP 3 FIX (BUY NOW SUPPORT)
    if 'buy_now' in session:
        item = session['buy_now']
        selected_items = [item]   # treat like cart
    else:
        selected_items = session.get('selected_items', [])

    if not selected_items:
        flash("No items selected!", "danger")
        return redirect('/user/cart')

    # 🔥 ADDRESS
    address_id = session.get('selected_address')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute(
        "SELECT * FROM addresses WHERE id=%s AND user_id=%s",
        (address_id, session['user_id'])
    )
    address = cursor.fetchone()

    conn.close()

    if not address:
        flash("Please select address!", "danger")
        return redirect('/user/address')

    # 💰 TOTAL
    total_amount = 0
    for item in selected_items:
        total_amount += float(item['price']) * float(item['quantity'])

    razorpay_amount = int(total_amount * 100)

    # 🔥 RAZORPAY ORDER
    razorpay_order = razorpay_client.order.create({
        "amount": razorpay_amount,
        "currency": "INR",
        "payment_capture": "1"
    })

    session['razorpay_order_id'] = razorpay_order['id']

    return render_template(
        "user/payment.html",
        amount=total_amount,
        order_amount=razorpay_amount,
        key_id=config.RAZORPAY_KEY_ID,
        order_id=razorpay_order['id'],
        address=address
    )

# =================================================================
# ---------24---------TEMP SUCCESS PAGE (Verification in Day 13)
# =================================================================
@app.route('/payment-success')
def payment_success():

    if 'user_id' not in session:
        return redirect('/user-login')

    payment_id = request.args.get('payment_id')
    razorpay_order_id = request.args.get('order_id')

    if not payment_id:
        flash("Payment failed!", "danger")
        return redirect('/user/cart')

    selected_items = session.get('selected_items', [])

    conn = get_db_connection()
    cursor = conn.cursor()

    form = session.get('address_data', {})
    amount = session.get('amount', 0)

    # 🔥 INSERT ORDER
    cursor.execute("""
        INSERT INTO orders (
            user_id, razorpay_order_id, razorpay_payment_id,
            amount, payment_status,
            full_name, phone,
            address_line1, address_line2,
            city, state, pincode
        )
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
    """, (
        session['user_id'],
        razorpay_order_id,
        payment_id,
        amount,
        "Paid",
        form.get('full_name'),
        form.get('phone'),
        form.get('address_line1'),
        form.get('address_line2'),
        form.get('city'),
        form.get('state'),
        form.get('pincode')
    ))

    conn.commit()
    order_id = cursor.lastrowid

    # 🔥 SAVE ITEMS
    for item in selected_items:
        cursor.execute("""
            INSERT INTO order_items (order_id, product_id, product_name, quantity, price)
            VALUES (%s, %s, %s, %s, %s)
        """, (
            order_id,
            item['id'],
            item['name'],
            item['quantity'],
            item['price']
        ))

    conn.commit()

    # 🔥 FIXED CART REMOVAL
    cart = session.get('cart', {})

    if selected_items and len(selected_items) == 1:
        ordered_pid = str(selected_items[0]['id'])

        if ordered_pid in cart:
            cart.pop(ordered_pid)

    session['cart'] = cart

    # 🔥 CLEAN SESSION
    session.pop('selected_items', None)
    session.pop('buy_product_id', None)

    cursor.close()
    conn.close()

    return redirect(f"/user/order-success/{order_id}")
#=================================================================


#=====================================================================
# ------------------------------
# Route: Verify Payment and Store Order
# ------------------------------
@app.route('/verify-payment', methods=['POST'])
def verify_payment():

    if 'user_id' not in session:
        flash("Please login to complete the payment.", "danger")
        return redirect('/user-login')

    razorpay_payment_id = request.form.get('razorpay_payment_id')
    razorpay_order_id = request.form.get('razorpay_order_id')
    razorpay_signature = request.form.get('razorpay_signature')

    if not (razorpay_payment_id and razorpay_order_id and razorpay_signature):
        flash("Payment verification failed (missing data).", "danger")
        return redirect('/user/cart')

    payload = {
        'razorpay_order_id': razorpay_order_id,
        'razorpay_payment_id': razorpay_payment_id,
        'razorpay_signature': razorpay_signature
    }

    try:
        razorpay_client.utility.verify_payment_signature(payload)

    except Exception as e:
        app.logger.error("Razorpay signature verification failed: %s", str(e))
        flash("Payment verification failed. Please contact support.", "danger")
        return redirect('/user/cart')

    # 🔥 SELECTED ITEMS
    selected_items = session.get('selected_items', [])

    if not selected_items:
        flash("No items selected.", "danger")
        return redirect('/user/cart')

    user_id = session['user_id']

    # 🔥 TOTAL
    total_amount = sum(item['price'] * item['quantity'] for item in selected_items)

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # 🔥 GET SELECTED ADDRESS
        address_id = session.get('selected_address')

        cursor2 = conn.cursor(dictionary=True)
        cursor2.execute(
            "SELECT * FROM addresses WHERE id=%s AND user_id=%s",
            (address_id, user_id)
        )
        addr = cursor2.fetchone()

        if not addr:
            flash("Address not found. Please select again.", "danger")
            return redirect('/user/address')

        # 🔥 INSERT ORDER WITH ADDRESS
        cursor.execute("""
            INSERT INTO orders (
                user_id, razorpay_order_id, razorpay_payment_id, amount, payment_status,
                full_name, phone, address, city, state, pincode
            )
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (
            user_id,
            razorpay_order_id,
            razorpay_payment_id,
            total_amount,
            'paid',
            addr['full_name'],
            addr['phone'],
            addr['address'],
            addr['city'],
            addr['state'],
            addr['pincode']
        ))

        order_db_id = cursor.lastrowid

        # 🔥 INSERT ORDER ITEMS
        for item in selected_items:
            product_id = int(item['id'])

            cursor.execute("""
                INSERT INTO order_items (order_id, product_id, product_name, quantity, price)
                VALUES (%s, %s, %s, %s, %s)
            """, (
                order_db_id,
                product_id,
                item['name'],
                item['quantity'],
                item['price']
            ))

        conn.commit()

        # 🔥 REMOVE ORDERED ITEMS FROM CART
        cart = session.get('cart', {})
        for item in selected_items:
            pid = str(item['id'])
            if pid in cart:
                cart.pop(pid)

        session['cart'] = cart

        # 🔥 CLEAN SESSION
        session.pop('selected_items', None)
        session.pop('razorpay_order_id', None)
        session.pop('selected_address', None)

        flash("Payment successful and order placed!", "success")
        return redirect(f"/user/order-success/{order_db_id}")

    except Exception as e:
        conn.rollback()
        app.logger.error("Order storage failed: %s\n%s", str(e), traceback.format_exc())
        flash("There was an error saving your order. Contact support.", "danger")
        return redirect('/user/cart')

    finally:
        cursor.close()
        conn.close()
#===========================================================================
@app.route('/user/order-success/<int:order_db_id>')
def order_success(order_db_id):

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # ✅ Fetch order (includes address fields also)
    cursor.execute("""
        SELECT * FROM orders 
        WHERE order_id=%s AND user_id=%s
    """, (order_db_id, session['user_id']))
    
    order = cursor.fetchone()

    # ✅ Fetch items
    cursor.execute("""
        SELECT * FROM order_items 
        WHERE order_id=%s
    """, (order_db_id,))
    
    items = cursor.fetchall()

    cursor.close()
    conn.close()

    if not order:
        flash("Order not found.", "danger")
        return redirect('/user/products')

    return render_template("user/order_success.html", order=order, items=items)

#===============================================================================

@app.route('/user/my-orders')
def my_orders():
    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM orders WHERE user_id=%s ORDER BY created_at DESC", (session['user_id'],))
    orders = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template("user/my_orders.html", orders=orders)


#===================================================================================
# ----------------------------
# GENERATE INVOICE PDF
# ----------------------------
@app.route("/user/download-invoice/<int:order_id>")
def download_invoice(order_id):

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    # Fetch order
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM orders WHERE order_id=%s AND user_id=%s",
                   (order_id, session['user_id']))
    order = cursor.fetchone()

    cursor.execute("SELECT * FROM order_items WHERE order_id=%s", (order_id,))
    items = cursor.fetchall()

    cursor.close()
    conn.close()

    if not order:
        flash("Order not found.", "danger")
        return redirect('/user/my-orders')

    # Render invoice HTML
    html = render_template("user/invoice.html", order=order, items=items)

    pdf = generate_pdf(html)
    if not pdf:
        flash("Error generating PDF", "danger")
        return redirect('/user/my-orders')

    # Prepare response
    response = make_response(pdf.getvalue())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f"attachment; filename=invoice_{order_id}.pdf"

    return response


#=====================================================================================

# ================================================================
# ADMIN: VIEW ONLY THIS ADMIN'S ORDERS
# ================================================================
@app.route('/admin/orders')
def admin_orders():

    if 'admin_id' not in session:
        flash("Please login as admin!", "danger")
        return redirect('/admin-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT DISTINCT 
            o.order_id, o.user_id, o.amount,
            o.payment_status, o.order_status, o.created_at,
            u.name AS username
        FROM orders o
        LEFT JOIN users u ON o.user_id = u.user_id
        INNER JOIN order_items oi ON o.order_id = oi.order_id
        INNER JOIN products p ON oi.product_id = p.product_id
        WHERE p.admin_id = %s
        ORDER BY o.created_at DESC
    """, (session['admin_id'],))

    orders = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template("admin/order_list.html", orders=orders)




#======================================================================

# ================================================================
# ADMIN: VIEW ONLY THIS ADMIN'S ORDER DETAILS
# ================================================================
@app.route('/admin/order/<int:order_id>')
def admin_order_details(order_id):

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT DISTINCT o.*
        FROM orders o
        INNER JOIN order_items oi ON o.order_id = oi.order_id
        INNER JOIN products p ON oi.product_id = p.product_id
        WHERE o.order_id = %s AND p.admin_id = %s
    """, (order_id, session['admin_id']))

    order = cursor.fetchone()

    if not order:
        cursor.close()
        conn.close()
        flash("Order not found or access denied!", "danger")
        return redirect('/admin/orders')

    cursor.execute("""
        SELECT oi.*, p.name, p.image
        FROM order_items oi
        INNER JOIN products p ON oi.product_id = p.product_id
        WHERE oi.order_id = %s AND p.admin_id = %s
    """, (order_id, session['admin_id']))

    items = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template("admin/order_details.html", order=order, items=items)

#======================================================================================

# ================================================================
# ADMIN: UPDATE ORDER STATUS
# ================================================================
@app.route("/admin/update-order-status/<int:order_id>", methods=['POST'])
def update_order_status(order_id):
    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    new_status = request.form.get('status')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("UPDATE orders SET order_status=%s WHERE order_id=%s",
                    (new_status, order_id))

    conn.commit()
    cursor.close()
    conn.close()

    flash("Order status updated successfully!", "success")
    return redirect(f"/admin/order/{order_id}")



#==================================================================
#==================================================================
#==================================================================
#==================================================================
#==================================================================
#==================================================================
#==================================================================
#==================================================================
#==================================================================
#==================================================================
#==================================================================
#==================================================================
#==================================================================
#==================================================================
#==================================================================
#==================================================================
#==================================================================
#==================================================================
#==================================================================
#==================================================================
#==================================================================
#==================================================================
#==================================================================
#==================================================================
#==================================================================
#==================================================================
#==================================================================
#==================================================================
#---------------------SUPER ADMIN---------------------------------- 
#---------------------SUPER ADMIN---------------------------------- 
#---------------------SUPER ADMIN---------------------------------- 
#---------------------SUPER ADMIN---------------------------------- 
#======================================== SUPER ADMIN MODULE ======================================================#
# ============================================================
# SUPER ADMIN REGISTER
# ============================================================
@app.route('/superadmin-register', methods=['GET', 'POST'])
def superadmin_register():

    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT * FROM superadmins WHERE email = %s", (email,))
        existing_superadmin = cursor.fetchone()

        if existing_superadmin:
            flash("Super Admin already exists with this email!", "danger")
            cursor.close()
            conn.close()
            return redirect('/superadmin-register')

        # ✅ FIXED LINE (only change)
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        cursor.execute(
            "INSERT INTO superadmins (name, email, password) VALUES (%s, %s, %s)",
            (name, email, hashed_password)
        )

        conn.commit()
        cursor.close()
        conn.close()

        flash("Super Admin registered successfully! Please login.", "success")
        return redirect('/superadmin-login')

    return render_template('superadmin/sa_register.html', hide_superadmin_nav=True)

# ============================================================
# SUPER ADMIN LOGIN
# ============================================================
@app.route('/superadmin-login', methods=['GET', 'POST'])
def superadmin_login():

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute(
            "SELECT * FROM superadmins WHERE email = %s",
            (email,)
        )

        superadmin = cursor.fetchone()

        cursor.close()
        conn.close()

        if superadmin and bcrypt.check_password_hash(superadmin['password'], password):

            session['superadmin_id'] = superadmin['superadmin_id']
            session['superadmin_name'] = superadmin['name']

            flash("Super Admin login successful!", "success")
            return redirect('/superadmin/dashboard')

        else:
            flash("Invalid Super Admin email or password!", "danger")
            return redirect('/superadmin-login')

    return render_template('superadmin/sa_login.html', hide_superadmin_nav=True)
# ============================================================
# SUPER ADMIN LOGIN CHECK DECORATOR
# ============================================================
def superadmin_required():
    if 'superadmin_id' not in session:
        flash("Please login as Super Admin!", "danger")
        return False
    return True


# ============================================================
# SUPER ADMIN DASHBOARD
# ============================================================
@app.route('/superadmin/dashboard')
def superadmin_dashboard():

    if not superadmin_required():
        return redirect('/superadmin-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT COUNT(*) AS total_admins FROM admin")
    total_admins = cursor.fetchone()['total_admins']

    cursor.execute("SELECT COUNT(*) AS total_products FROM products")
    total_products = cursor.fetchone()['total_products']

    cursor.execute("SELECT COUNT(*) AS total_orders FROM orders")
    total_orders = cursor.fetchone()['total_orders']

    cursor.execute("SELECT IFNULL(SUM(amount), 0) AS total_revenue FROM orders")
    total_revenue = cursor.fetchone()['total_revenue']

    cursor.close()
    conn.close()

    return render_template(
        'superadmin/sa_dashboard.html',
        total_admins=total_admins,
        total_products=total_products,
        total_orders=total_orders,
        total_revenue=total_revenue
    )


# ============================================================
# VIEW ALL ADMINS
# ============================================================
@app.route('/superadmin/admins')
def superadmin_admins():

    if not superadmin_required():
        return redirect('/superadmin-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM admin ORDER BY admin_id DESC")
    admins = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template('superadmin/sa_admins.html', admins=admins)

# ============================================================
# APPROVE ADMIN
# ============================================================
@app.route('/superadmin/approve-admin/<int:admin_id>')
def approve_admin(admin_id):

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM admin WHERE admin_id=%s", (admin_id,))
    admin = cursor.fetchone()

    if not admin:
        cursor.close()
        conn.close()
        flash("Admin not found!", "danger")
        return redirect('/superadmin/admins')

    cursor.execute("""
        UPDATE admin
        SET status = 'approved'
        WHERE admin_id = %s
    """, (admin_id,))

    conn.commit()

    cursor.close()
    conn.close()

    msg = Message(
        subject="SmartCart Admin Approved",
        sender=app.config['MAIL_USERNAME'],
        recipients=[admin['email']]
    )
    msg.body = "Your admin registration has been approved. You can now login."
    mail.send(msg)

    flash("Admin approved successfully!", "success")
    return redirect('/superadmin/admins')

# ============================================================
# REJECT ADMIN
# ============================================================
@app.route('/superadmin/reject-admin/<int:admin_id>')
def reject_admin(admin_id):

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM admin WHERE admin_id=%s", (admin_id,))
    admin = cursor.fetchone()

    if not admin:
        cursor.close()
        conn.close()
        flash("Admin not found!", "danger")
        return redirect('/superadmin/admins')

    cursor.execute("""
        UPDATE admin
        SET status = 'rejected'
        WHERE admin_id = %s
    """, (admin_id,))

    conn.commit()

    cursor.close()
    conn.close()

    message = Message(
        subject="SmartCart Admin Registration Rejected",
        sender=app.config['MAIL_USERNAME'],
        recipients=[admin['email']]
    )
    message.body = "Your admin registration has been rejected by Super Admin."
    mail.send(message)

    flash("Admin rejected successfully!", "success")
    return redirect('/superadmin/admins')


# ============================================================
# VIEW ALL PRODUCTS
# ============================================================
@app.route('/superadmin/products')
def superadmin_products():

    if not superadmin_required():
        return redirect('/superadmin-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT products.*, admin.name AS admin_name
        FROM products
        LEFT JOIN admin ON products.admin_id = admin.admin_id
        ORDER BY products.product_id DESC
    """)
    products = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template('superadmin/sa_products.html', products=products)


# ============================================================
# VIEW ALL ORDERS
# ============================================================
@app.route('/superadmin/orders')
def superadmin_orders():

    if not superadmin_required():
        return redirect('/superadmin-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT *
        FROM orders
        ORDER BY order_id DESC
    """)
    orders = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template('superadmin/sa_orders.html', orders=orders)


# ============================================================
# VIEW REVENUE
# ============================================================
@app.route('/superadmin/revenue')
def superadmin_revenue():

    if not superadmin_required():
        return redirect('/superadmin-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT IFNULL(SUM(amount), 0) AS total_revenue FROM orders")
    total_revenue = cursor.fetchone()['total_revenue']

    cursor.execute("""
        SELECT 
            admin.name AS admin_name,
            IFNULL(SUM(orders.amount), 0) AS revenue
        FROM admin
        LEFT JOIN products ON admin.admin_id = products.admin_id
        LEFT JOIN orders ON products.product_id = orders.order_id
        GROUP BY admin.admin_id
    """)
    admin_revenue = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        'superadmin/sa_revenue.html',
        total_revenue=total_revenue,
        admin_revenue=admin_revenue
    )

#=========================================================
#      SUPER ADMIN FORGOT PASSWORD
#=====================================================

@app.route('/sa-forgot-password', methods=['GET', 'POST'])
def sa_forgot_password():

    if request.method == 'GET':
        return render_template("superadmin/sa_forgot_password.html", hide_superadmin_nav=True)

    email = request.form['email']

    # Check email exists
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM superadmins WHERE email=%s", (email,))
    admin = cursor.fetchone()
    cursor.close()
    conn.close()

    if not admin:
        flash("Email not found!", "danger")
        return redirect('/sa-forgot-password')

    # Generate OTP
    otp = random.randint(100000, 999999)

    # Store in session
    session['reset_email'] = email
    session['reset_otp'] = str(otp)

    # Send email
    msg = Message(
        subject="Password Reset OTP",
        sender=config.MAIL_USERNAME,
        recipients=[email]
    )
    msg.body = f"Your OTP is: {otp}"
    mail.send(msg)

    flash("OTP sent to your email!", "success")
    return redirect('/sa-verify-reset-otp')

# VERIFY RESET OTP
@app.route('/sa-verify-reset-otp', methods=['GET', 'POST'])
def sa_verify_reset_otp():

    # Check forgot password step completed
    if 'reset_email' not in session:
        flash("Please enter your email first!", "warning")
        return redirect('/sa-forgot-password')

    if request.method == 'GET':
        return render_template(
            "superadmin/sa_verify_reset_otp.html",
            hide_superadmin_nav=True
        )

    user_otp = request.form['otp']

    # Check OTP
    if user_otp != session.get('reset_otp'):
        flash("Invalid OTP!", "danger")
        return redirect('/sa-verify-reset-otp')

    # Mark OTP as verified
    session['otp_verified'] = True

    flash("OTP Verified! Now reset your password.", "success")
    return redirect('/sa-reset-password')


# RESET PASSWORD
@app.route('/sa-reset-password', methods=['GET', 'POST'])
def sa_reset_password():

    # 🔒 Step 1: Check email exists in session
    if 'reset_email' not in session:
        flash("Please start from forgot password!", "warning")
        return redirect('/sa-forgot-password')

    # 🔒 Step 2: Check OTP verified
    if not session.get('otp_verified'):
        flash("Please verify OTP first!", "warning")
        return redirect('/sa-verify-reset-otp')

    if request.method == 'GET':
        return render_template(
            "superadmin/sa_reset_password.html",
            hide_superadmin_nav=True
        )

    new_password = request.form['password']

    # ✅ Hash password (IMPORTANT FIX)
    hashed_password = bcrypt.hashpw(
        new_password.encode('utf-8'),
        bcrypt.gensalt()
    ).decode('utf-8')

    # Update DB
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE superadmins SET password=%s WHERE email=%s",
        (hashed_password, session.get('reset_email'))
    )
    conn.commit()
    cursor.close()
    conn.close()

    # 🧹 Clear session
    session.pop('reset_email', None)
    session.pop('reset_otp', None)
    session.pop('otp_verified', None)

    flash("Password updated successfully!", "success")
    return redirect('/superadmin-login')

# ============================================================
# SUPER ADMIN LOGOUT
# ============================================================
@app.route('/superadmin/logout')
def superadmin_logout():
    session.clear()
    flash("Logged out successfully!", "success")
    return redirect('/superadmin-login')

# ------------------------- RUN APP ------------------------
if __name__ == '__main__':
    app.run(debug=True)
