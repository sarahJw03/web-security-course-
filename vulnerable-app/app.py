"""
Vulnerable Web Application - IDOR Demonstration
This application intentionally contains IDOR vulnerabilities for educational purposes.
DO NOT use this code in production environments.
"""

from flask import Flask, request, jsonify, session, redirect, url_for, render_template_string
import sqlite3
import os

app = Flask(__name__)
app.secret_key = 'super-secret-key-for-demo'

DB_PATH = os.path.join(os.path.dirname(__file__), 'database.db')


def get_db():
    """Get database connection."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initialize the database with sample data."""
    conn = get_db()
    cursor = conn.cursor()

    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT NOT NULL,
            full_name TEXT NOT NULL,
            phone TEXT,
            role TEXT DEFAULT 'user'
        )
    ''')

    # Create orders table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            product TEXT NOT NULL,
            quantity INTEGER NOT NULL,
            total_price REAL NOT NULL,
            status TEXT DEFAULT 'pending',
            shipping_address TEXT,
            credit_card_last4 TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')

    # Create messages table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL,
            receiver_id INTEGER NOT NULL,
            subject TEXT NOT NULL,
            body TEXT NOT NULL,
            is_read INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (sender_id) REFERENCES users(id),
            FOREIGN KEY (receiver_id) REFERENCES users(id)
        )
    ''')

    # Insert sample users
    users = [
        ('alice', 'password123', 'alice@example.com', 'Alice Cohen', '050-1234567', 'user'),
        ('bob', 'password456', 'bob@example.com', 'Bob Levi', '052-9876543', 'user'),
        ('charlie', 'password789', 'charlie@example.com', 'Charlie Admin', '054-5555555', 'admin'),
        ('david', 'password321', 'david@example.com', 'David Mizrahi', '053-1112233', 'user'),
    ]

    for user in users:
        try:
            cursor.execute(
                'INSERT INTO users (username, password, email, full_name, phone, role) VALUES (?, ?, ?, ?, ?, ?)',
                user
            )
        except sqlite3.IntegrityError:
            pass

    # Insert sample orders
    orders = [
        (1, 'Laptop Dell XPS 15', 1, 5499.99, 'delivered', 'Herzliya, Israel', '4532'),
        (1, 'Wireless Mouse', 2, 199.90, 'pending', 'Herzliya, Israel', '4532'),
        (2, 'iPhone 15 Pro', 1, 4999.00, 'shipped', 'Tel Aviv, Israel', '8821'),
        (2, 'AirPods Pro', 1, 899.00, 'delivered', 'Tel Aviv, Israel', '8821'),
        (3, 'MacBook Pro M3', 1, 8999.00, 'pending', 'Haifa, Israel', '1234'),
        (4, 'Samsung Galaxy S24', 1, 3799.00, 'shipped', 'Beer Sheva, Israel', '6677'),
    ]

    for order in orders:
        try:
            cursor.execute(
                'INSERT INTO orders (user_id, product, quantity, total_price, status, shipping_address, credit_card_last4) VALUES (?, ?, ?, ?, ?, ?, ?)',
                order
            )
        except:
            pass

    # Insert sample messages
    messages = [
        (3, 1, 'Welcome to the platform', 'Hello Alice, welcome to our platform! Your account is ready.', 1),
        (3, 2, 'Welcome to the platform', 'Hello Bob, welcome to our platform! Your account is ready.', 0),
        (1, 2, 'Meeting tomorrow', 'Hi Bob, can we meet tomorrow at 10am?', 0),
        (2, 1, 'Re: Meeting tomorrow', 'Sure Alice, see you then!', 0),
        (3, 4, 'Admin Notice', 'David, please update your profile information. - Admin', 0),
    ]

    for msg in messages:
        try:
            cursor.execute(
                'INSERT INTO messages (sender_id, receiver_id, subject, body, is_read) VALUES (?, ?, ?, ?, ?)',
                msg
            )
        except:
            pass

    conn.commit()
    conn.close()


# HTML Templates
LOGIN_PAGE = '''
<!DOCTYPE html>
<html dir="ltr" lang="en">
<head>
    <meta charset="UTF-8">
    <title>SecureShop - Login</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, sans-serif; background: #1a1a2e; color: #eee; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
        .login-container { background: #16213e; padding: 40px; border-radius: 12px; box-shadow: 0 8px 32px rgba(0,0,0,0.3); width: 400px; }
        h1 { text-align: center; color: #e94560; margin-bottom: 30px; font-size: 28px; }
        .subtitle { text-align: center; color: #888; margin-bottom: 20px; font-size: 14px; }
        input { width: 100%; padding: 12px 16px; margin: 8px 0; border: 1px solid #333; border-radius: 8px; background: #0f3460; color: #eee; font-size: 16px; }
        input:focus { outline: none; border-color: #e94560; }
        button { width: 100%; padding: 14px; margin-top: 16px; background: #e94560; color: white; border: none; border-radius: 8px; font-size: 16px; cursor: pointer; font-weight: bold; }
        button:hover { background: #c73e54; }
        .error { color: #ff6b6b; text-align: center; margin-top: 10px; }
        .users-hint { margin-top: 20px; padding: 15px; background: #0f3460; border-radius: 8px; font-size: 12px; color: #888; }
        .users-hint h3 { color: #e94560; margin-bottom: 8px; }
    </style>
</head>
<body>
    <div class="login-container">
        <h1>🛒 SecureShop</h1>
        <p class="subtitle">E-Commerce Platform - Demo Environment</p>
        <form method="POST" action="/login">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
        {% if error %}<p class="error">{{ error }}</p>{% endif %}
        <div class="users-hint">
            <h3>Demo Accounts:</h3>
            <p>alice / password123 (User, ID: 1)</p>
            <p>bob / password456 (User, ID: 2)</p>
            <p>charlie / password789 (Admin, ID: 3)</p>
            <p>david / password321 (User, ID: 4)</p>
        </div>
    </div>
</body>
</html>
'''

DASHBOARD_PAGE = '''
<!DOCTYPE html>
<html dir="ltr" lang="en">
<head>
    <meta charset="UTF-8">
    <title>SecureShop - Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, sans-serif; background: #1a1a2e; color: #eee; }
        .navbar { background: #16213e; padding: 15px 30px; display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #e94560; }
        .navbar h1 { color: #e94560; font-size: 22px; }
        .navbar .user-info { color: #888; }
        .navbar a { color: #e94560; text-decoration: none; margin-left: 20px; }
        .container { max-width: 1200px; margin: 30px auto; padding: 0 20px; }
        .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin-top: 20px; }
        .card { background: #16213e; padding: 25px; border-radius: 12px; border: 1px solid #333; }
        .card h2 { color: #e94560; margin-bottom: 15px; font-size: 18px; }
        .card a { display: inline-block; padding: 10px 20px; background: #e94560; color: white; text-decoration: none; border-radius: 6px; margin-top: 10px; font-size: 14px; }
        .card a:hover { background: #c73e54; }
        .card p { color: #aaa; line-height: 1.6; }
        .warning { background: #ff6b6b22; border: 1px solid #ff6b6b; padding: 15px; border-radius: 8px; margin-top: 20px; }
        .warning h3 { color: #ff6b6b; margin-bottom: 5px; }
    </style>
</head>
<body>
    <div class="navbar">
        <h1>🛒 SecureShop Dashboard</h1>
        <div class="user-info">
            Logged in as: <strong>{{ user.username }}</strong> ({{ user.role }}) |
            <a href="/profile/{{ user.id }}">My Profile</a>
            <a href="/orders/{{ user.id }}">My Orders</a>
            <a href="/messages/{{ user.id }}">My Messages</a>
            <a href="/logout">Logout</a>
        </div>
    </div>
    <div class="container">
        <div class="warning">
            <h3>⚠️ Vulnerable Demo Application</h3>
            <p>This application intentionally contains IDOR vulnerabilities for educational purposes.</p>
        </div>
        <div class="cards">
            <div class="card">
                <h2>👤 User Profile</h2>
                <p>View and manage your personal profile information including email, phone, and full name.</p>
                <p><strong>API:</strong> GET /api/user/{id}</p>
                <a href="/profile/{{ user.id }}">View Profile</a>
            </div>
            <div class="card">
                <h2>📦 Orders</h2>
                <p>View your order history, including product details, shipping address, and payment info.</p>
                <p><strong>API:</strong> GET /api/orders/{user_id}</p>
                <a href="/orders/{{ user.id }}">View Orders</a>
            </div>
            <div class="card">
                <h2>✉️ Messages</h2>
                <p>Read your private messages from other users and administrators.</p>
                <p><strong>API:</strong> GET /api/messages/{id}</p>
                <a href="/messages/{{ user.id }}">View Messages</a>
            </div>
            <div class="card">
                <h2>🔧 Edit Profile</h2>
                <p>Update your profile information. Change email, phone number, or full name.</p>
                <p><strong>API:</strong> PUT /api/user/{id}</p>
                <a href="/edit-profile/{{ user.id }}">Edit Profile</a>
            </div>
        </div>
    </div>
</body>
</html>
'''

PROFILE_PAGE = '''
<!DOCTYPE html>
<html dir="ltr" lang="en">
<head>
    <meta charset="UTF-8">
    <title>SecureShop - Profile</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, sans-serif; background: #1a1a2e; color: #eee; }
        .navbar { background: #16213e; padding: 15px 30px; display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #e94560; }
        .navbar h1 { color: #e94560; }
        .navbar a { color: #e94560; text-decoration: none; margin-left: 20px; }
        .container { max-width: 800px; margin: 30px auto; padding: 0 20px; }
        .profile-card { background: #16213e; padding: 30px; border-radius: 12px; border: 1px solid #333; }
        .profile-card h2 { color: #e94560; margin-bottom: 20px; }
        .field { display: flex; padding: 12px 0; border-bottom: 1px solid #333; }
        .field .label { width: 150px; color: #888; font-weight: bold; }
        .field .value { color: #eee; }
        .back-link { display: inline-block; margin-top: 20px; color: #e94560; text-decoration: none; }
    </style>
</head>
<body>
    <div class="navbar">
        <h1>🛒 SecureShop</h1>
        <div><a href="/dashboard">Dashboard</a><a href="/logout">Logout</a></div>
    </div>
    <div class="container">
        <div class="profile-card">
            <h2>👤 User Profile (ID: {{ profile.id }})</h2>
            <div class="field"><span class="label">Username:</span><span class="value">{{ profile.username }}</span></div>
            <div class="field"><span class="label">Full Name:</span><span class="value">{{ profile.full_name }}</span></div>
            <div class="field"><span class="label">Email:</span><span class="value">{{ profile.email }}</span></div>
            <div class="field"><span class="label">Phone:</span><span class="value">{{ profile.phone }}</span></div>
            <div class="field"><span class="label">Role:</span><span class="value">{{ profile.role }}</span></div>
        </div>
        <a class="back-link" href="/dashboard">← Back to Dashboard</a>
    </div>
</body>
</html>
'''

ORDERS_PAGE = '''
<!DOCTYPE html>
<html dir="ltr" lang="en">
<head>
    <meta charset="UTF-8">
    <title>SecureShop - Orders</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, sans-serif; background: #1a1a2e; color: #eee; }
        .navbar { background: #16213e; padding: 15px 30px; display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #e94560; }
        .navbar h1 { color: #e94560; }
        .navbar a { color: #e94560; text-decoration: none; margin-left: 20px; }
        .container { max-width: 900px; margin: 30px auto; padding: 0 20px; }
        h2 { color: #e94560; margin-bottom: 20px; }
        table { width: 100%; border-collapse: collapse; background: #16213e; border-radius: 12px; overflow: hidden; }
        th { background: #0f3460; padding: 14px; text-align: left; color: #e94560; }
        td { padding: 12px 14px; border-bottom: 1px solid #333; }
        .status-delivered { color: #4ecdc4; }
        .status-shipped { color: #f9c74f; }
        .status-pending { color: #ff6b6b; }
        .back-link { display: inline-block; margin-top: 20px; color: #e94560; text-decoration: none; }
    </style>
</head>
<body>
    <div class="navbar">
        <h1>🛒 SecureShop</h1>
        <div><a href="/dashboard">Dashboard</a><a href="/logout">Logout</a></div>
    </div>
    <div class="container">
        <h2>📦 Orders for User ID: {{ user_id }}</h2>
        <table>
            <tr><th>Order ID</th><th>Product</th><th>Qty</th><th>Total</th><th>Status</th><th>Address</th><th>Card (last 4)</th></tr>
            {% for order in orders %}
            <tr>
                <td>#{{ order.id }}</td>
                <td>{{ order.product }}</td>
                <td>{{ order.quantity }}</td>
                <td>₪{{ "%.2f"|format(order.total_price) }}</td>
                <td class="status-{{ order.status }}">{{ order.status }}</td>
                <td>{{ order.shipping_address }}</td>
                <td>****{{ order.credit_card_last4 }}</td>
            </tr>
            {% endfor %}
        </table>
        <a class="back-link" href="/dashboard">← Back to Dashboard</a>
    </div>
</body>
</html>
'''

MESSAGES_PAGE = '''
<!DOCTYPE html>
<html dir="ltr" lang="en">
<head>
    <meta charset="UTF-8">
    <title>SecureShop - Messages</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, sans-serif; background: #1a1a2e; color: #eee; }
        .navbar { background: #16213e; padding: 15px 30px; display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #e94560; }
        .navbar h1 { color: #e94560; }
        .navbar a { color: #e94560; text-decoration: none; margin-left: 20px; }
        .container { max-width: 800px; margin: 30px auto; padding: 0 20px; }
        h2 { color: #e94560; margin-bottom: 20px; }
        .message { background: #16213e; padding: 20px; border-radius: 12px; border: 1px solid #333; margin-bottom: 15px; }
        .message h3 { color: #e94560; margin-bottom: 8px; }
        .message .meta { color: #888; font-size: 13px; margin-bottom: 10px; }
        .message .body { color: #ccc; line-height: 1.6; }
        .back-link { display: inline-block; margin-top: 20px; color: #e94560; text-decoration: none; }
    </style>
</head>
<body>
    <div class="navbar">
        <h1>🛒 SecureShop</h1>
        <div><a href="/dashboard">Dashboard</a><a href="/logout">Logout</a></div>
    </div>
    <div class="container">
        <h2>✉️ Messages</h2>
        {% for msg in messages %}
        <div class="message">
            <h3>{{ msg.subject }}</h3>
            <div class="meta">From: User #{{ msg.sender_id }} | To: User #{{ msg.receiver_id }} | {{ msg.created_at }}</div>
            <div class="body">{{ msg.body }}</div>
        </div>
        {% endfor %}
        <a class="back-link" href="/dashboard">← Back to Dashboard</a>
    </div>
</body>
</html>
'''


# ============================================================
# ROUTES - All vulnerable to IDOR (no authorization checks)
# ============================================================

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect('/dashboard')
    return render_template_string(LOGIN_PAGE, error=None)


@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    conn = get_db()
    user = conn.execute(
        'SELECT * FROM users WHERE username = ? AND password = ?',
        (username, password)
    ).fetchone()
    conn.close()

    if user:
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['role'] = user['role']
        return redirect('/dashboard')

    return render_template_string(LOGIN_PAGE, error='Invalid credentials')


@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/')

    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    conn.close()
    return render_template_string(DASHBOARD_PAGE, user=user)


# VULNERABLE: No authorization check - any logged-in user can view any profile
@app.route('/profile/<int:user_id>')
def profile(user_id):
    if 'user_id' not in session:
        return redirect('/')

    conn = get_db()
    profile = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()

    if not profile:
        return 'User not found', 404

    # VULNERABILITY: Does NOT check if session user_id matches requested user_id
    return render_template_string(PROFILE_PAGE, profile=profile)


# VULNERABLE: No authorization check - any logged-in user can view any user's orders
@app.route('/orders/<int:user_id>')
def orders(user_id):
    if 'user_id' not in session:
        return redirect('/')

    conn = get_db()
    user_orders = conn.execute('SELECT * FROM orders WHERE user_id = ?', (user_id,)).fetchall()
    conn.close()

    # VULNERABILITY: Does NOT check if session user_id matches requested user_id
    return render_template_string(ORDERS_PAGE, orders=user_orders, user_id=user_id)


# VULNERABLE: No authorization check - any logged-in user can read any message
@app.route('/messages/<int:msg_id>')
def messages(msg_id):
    if 'user_id' not in session:
        return redirect('/')

    conn = get_db()
    user_messages = conn.execute(
        'SELECT * FROM messages WHERE receiver_id = ? OR sender_id = ?',
        (msg_id, msg_id)
    ).fetchall()
    conn.close()

    # VULNERABILITY: Does NOT check if session user_id matches requested msg_id
    return render_template_string(MESSAGES_PAGE, messages=user_messages)


# ============================================================
# API ENDPOINTS - Also vulnerable to IDOR
# ============================================================

# VULNERABLE API: Get user profile by ID
@app.route('/api/user/<int:user_id>', methods=['GET'])
def api_get_user(user_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    conn = get_db()
    user = conn.execute('SELECT id, username, email, full_name, phone, role FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()

    if not user:
        return jsonify({'error': 'User not found'}), 404

    # VULNERABILITY: No check if requesting user is authorized to view this profile
    return jsonify(dict(user))


# VULNERABLE API: Update user profile by ID
@app.route('/api/user/<int:user_id>', methods=['PUT'])
def api_update_user(user_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json()
    conn = get_db()

    # VULNERABILITY: Any authenticated user can modify any other user's profile
    if 'email' in data:
        conn.execute('UPDATE users SET email = ? WHERE id = ?', (data['email'], user_id))
    if 'phone' in data:
        conn.execute('UPDATE users SET phone = ? WHERE id = ?', (data['phone'], user_id))
    if 'full_name' in data:
        conn.execute('UPDATE users SET full_name = ? WHERE id = ?', (data['full_name'], user_id))

    conn.commit()
    user = conn.execute('SELECT id, username, email, full_name, phone, role FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()

    return jsonify({'message': 'Profile updated', 'user': dict(user)})


# VULNERABLE API: Get orders by user ID
@app.route('/api/orders/<int:user_id>', methods=['GET'])
def api_get_orders(user_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    conn = get_db()
    orders = conn.execute('SELECT * FROM orders WHERE user_id = ?', (user_id,)).fetchall()
    conn.close()

    # VULNERABILITY: No check if requesting user owns these orders
    return jsonify([dict(order) for order in orders])


# VULNERABLE API: Delete order by order ID
@app.route('/api/orders/<int:order_id>', methods=['DELETE'])
def api_delete_order(order_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    conn = get_db()

    # VULNERABILITY: Any authenticated user can delete any order
    conn.execute('DELETE FROM orders WHERE id = ?', (order_id,))
    conn.commit()
    conn.close()

    return jsonify({'message': f'Order {order_id} deleted successfully'})


# VULNERABLE API: Get specific message
@app.route('/api/messages/<int:msg_id>', methods=['GET'])
def api_get_message(msg_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    conn = get_db()
    message = conn.execute('SELECT * FROM messages WHERE id = ?', (msg_id,)).fetchone()
    conn.close()

    if not message:
        return jsonify({'error': 'Message not found'}), 404

    # VULNERABILITY: No check if requesting user is sender or receiver
    return jsonify(dict(message))


if __name__ == '__main__':
    init_db()
    print("[*] Starting Vulnerable SecureShop Application...")
    print("[*] WARNING: This application contains intentional IDOR vulnerabilities!")
    print("[*] Running on http://0.0.0.0:5000")
    app.run(host='0.0.0.0', port=5000, debug=True)
