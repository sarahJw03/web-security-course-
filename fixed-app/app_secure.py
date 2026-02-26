"""
Secure Web Application - IDOR Mitigated Version
This application demonstrates proper authorization checks to prevent IDOR vulnerabilities.
"""

from flask import Flask, request, jsonify, session, redirect, url_for, render_template_string
from functools import wraps
import sqlite3
import os
import uuid
import logging

app = Flask(__name__)
app.secret_key = 'super-secret-key-for-demo'

DB_PATH = os.path.join(os.path.dirname(__file__), 'database_secure.db')

# Configure logging for access control events
logging.basicConfig(
    filename='access_control.log',
    level=logging.WARNING,
    format='%(asctime)s - %(levelname)s - %(message)s'
)


def get_db():
    """Get database connection."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initialize the database with sample data using UUIDs."""
    conn = get_db()
    cursor = conn.cursor()

    # Create users table with UUID
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            uuid TEXT UNIQUE NOT NULL,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT NOT NULL,
            full_name TEXT NOT NULL,
            phone TEXT,
            role TEXT DEFAULT 'user'
        )
    ''')

    # Create orders table with UUID
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            uuid TEXT UNIQUE NOT NULL,
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

    # Create messages table with UUID
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            uuid TEXT UNIQUE NOT NULL,
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

    # Insert sample users with UUIDs
    users = [
        (str(uuid.uuid4()), 'alice', 'password123', 'alice@example.com', 'Alice Cohen', '050-1234567', 'user'),
        (str(uuid.uuid4()), 'bob', 'password456', 'bob@example.com', 'Bob Levi', '052-9876543', 'user'),
        (str(uuid.uuid4()), 'charlie', 'password789', 'charlie@example.com', 'Charlie Admin', '054-5555555', 'admin'),
        (str(uuid.uuid4()), 'david', 'password321', 'david@example.com', 'David Mizrahi', '053-1112233', 'user'),
    ]

    for user in users:
        try:
            cursor.execute(
                'INSERT INTO users (uuid, username, password, email, full_name, phone, role) VALUES (?, ?, ?, ?, ?, ?, ?)',
                user
            )
        except sqlite3.IntegrityError:
            pass

    # Insert sample orders with UUIDs
    orders = [
        (str(uuid.uuid4()), 1, 'Laptop Dell XPS 15', 1, 5499.99, 'delivered', 'Herzliya, Israel', '4532'),
        (str(uuid.uuid4()), 1, 'Wireless Mouse', 2, 199.90, 'pending', 'Herzliya, Israel', '4532'),
        (str(uuid.uuid4()), 2, 'iPhone 15 Pro', 1, 4999.00, 'shipped', 'Tel Aviv, Israel', '8821'),
        (str(uuid.uuid4()), 2, 'AirPods Pro', 1, 899.00, 'delivered', 'Tel Aviv, Israel', '8821'),
    ]

    for order in orders:
        try:
            cursor.execute(
                'INSERT INTO orders (uuid, user_id, product, quantity, total_price, status, shipping_address, credit_card_last4) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                order
            )
        except:
            pass

    # Insert sample messages with UUIDs
    messages = [
        (str(uuid.uuid4()), 3, 1, 'Welcome to the platform', 'Hello Alice, welcome!', 1),
        (str(uuid.uuid4()), 3, 2, 'Welcome to the platform', 'Hello Bob, welcome!', 0),
        (str(uuid.uuid4()), 1, 2, 'Meeting tomorrow', 'Hi Bob, can we meet tomorrow?', 0),
    ]

    for msg in messages:
        try:
            cursor.execute(
                'INSERT INTO messages (uuid, sender_id, receiver_id, subject, body, is_read) VALUES (?, ?, ?, ?, ?, ?)',
                msg
            )
        except:
            pass

    conn.commit()
    conn.close()


# ============================================================
# SECURITY MIDDLEWARE: Authorization decorator
# ============================================================

def login_required(f):
    """Decorator to ensure user is authenticated."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function


def authorize_user(f):
    """Decorator to enforce authorization - user can only access own resources."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401

        # Check if the requested user_id matches the session user
        requested_user_id = kwargs.get('user_id')
        if requested_user_id and requested_user_id != session['user_id']:
            # Log the unauthorized access attempt
            logging.warning(
                f"IDOR ATTEMPT BLOCKED: User {session['user_id']} ({session.get('username')}) "
                f"tried to access resource of user {requested_user_id}"
            )
            return jsonify({
                'error': 'Forbidden',
                'message': 'You are not authorized to access this resource'
            }), 403

        return f(*args, **kwargs)
    return decorated_function


# ============================================================
# SECURE API ENDPOINTS
# ============================================================

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
        session['user_uuid'] = user['uuid']
        return redirect('/dashboard')

    return 'Invalid credentials', 401


# SECURE: Uses session to determine which profile to show
@app.route('/api/user/me', methods=['GET'])
@login_required
def api_get_own_profile():
    """FIX 1: Use session-based access instead of user-supplied ID."""
    conn = get_db()
    user = conn.execute(
        'SELECT uuid, username, email, full_name, phone, role FROM users WHERE id = ?',
        (session['user_id'],)
    ).fetchone()
    conn.close()

    if not user:
        return jsonify({'error': 'User not found'}), 404

    return jsonify(dict(user))


# SECURE: Authorization check before accessing profile
@app.route('/api/user/<int:user_id>', methods=['GET'])
@login_required
@authorize_user
def api_get_user(user_id):
    """FIX 2: Authorization decorator ensures user can only access own profile."""
    conn = get_db()
    user = conn.execute(
        'SELECT uuid, username, email, full_name, phone, role FROM users WHERE id = ?',
        (user_id,)
    ).fetchone()
    conn.close()

    if not user:
        return jsonify({'error': 'User not found'}), 404

    return jsonify(dict(user))


# SECURE: Authorization check before updating profile
@app.route('/api/user/<int:user_id>', methods=['PUT'])
@login_required
@authorize_user
def api_update_user(user_id):
    """FIX 3: Authorization check prevents modifying other users' profiles."""
    data = request.get_json()
    conn = get_db()

    allowed_fields = ['email', 'phone', 'full_name']
    for field in allowed_fields:
        if field in data:
            conn.execute(f'UPDATE users SET {field} = ? WHERE id = ?', (data[field], user_id))

    conn.commit()
    user = conn.execute(
        'SELECT uuid, username, email, full_name, phone, role FROM users WHERE id = ?',
        (user_id,)
    ).fetchone()
    conn.close()

    return jsonify({'message': 'Profile updated', 'user': dict(user)})


# SECURE: Scoped query - only returns orders belonging to the authenticated user
@app.route('/api/orders', methods=['GET'])
@login_required
def api_get_my_orders():
    """FIX 4: Query scoped to authenticated user's orders only."""
    conn = get_db()
    orders = conn.execute(
        'SELECT uuid, product, quantity, total_price, status, shipping_address, credit_card_last4, created_at '
        'FROM orders WHERE user_id = ?',
        (session['user_id'],)
    ).fetchall()
    conn.close()

    return jsonify([dict(order) for order in orders])


# SECURE: Verify ownership before deleting order
@app.route('/api/orders/<order_uuid>', methods=['DELETE'])
@login_required
def api_delete_order(order_uuid):
    """FIX 5: Verify order ownership + use UUID instead of sequential ID."""
    conn = get_db()

    # First verify the order belongs to the authenticated user
    order = conn.execute(
        'SELECT * FROM orders WHERE uuid = ? AND user_id = ?',
        (order_uuid, session['user_id'])
    ).fetchone()

    if not order:
        logging.warning(
            f"IDOR ATTEMPT BLOCKED: User {session['user_id']} tried to delete order {order_uuid}"
        )
        conn.close()
        return jsonify({'error': 'Order not found or access denied'}), 403

    conn.execute('DELETE FROM orders WHERE uuid = ? AND user_id = ?', (order_uuid, session['user_id']))
    conn.commit()
    conn.close()

    return jsonify({'message': 'Order deleted successfully'})


# SECURE: Only return messages where user is sender or receiver
@app.route('/api/messages', methods=['GET'])
@login_required
def api_get_my_messages():
    """FIX 6: Query scoped to messages involving the authenticated user."""
    conn = get_db()
    messages = conn.execute(
        'SELECT uuid, sender_id, receiver_id, subject, body, is_read, created_at '
        'FROM messages WHERE receiver_id = ? OR sender_id = ?',
        (session['user_id'], session['user_id'])
    ).fetchall()
    conn.close()

    return jsonify([dict(msg) for msg in messages])


# SECURE: Verify message access rights
@app.route('/api/messages/<msg_uuid>', methods=['GET'])
@login_required
def api_get_message(msg_uuid):
    """FIX 7: Verify user is sender or receiver + use UUID."""
    conn = get_db()
    message = conn.execute(
        'SELECT * FROM messages WHERE uuid = ? AND (sender_id = ? OR receiver_id = ?)',
        (msg_uuid, session['user_id'], session['user_id'])
    ).fetchone()
    conn.close()

    if not message:
        logging.warning(
            f"IDOR ATTEMPT BLOCKED: User {session['user_id']} tried to access message {msg_uuid}"
        )
        return jsonify({'error': 'Message not found or access denied'}), 403

    return jsonify(dict(message))


if __name__ == '__main__':
    init_db()
    print("[*] Starting SECURE SecureShop Application...")
    print("[*] All IDOR vulnerabilities have been mitigated!")
    print("[*] Running on http://0.0.0.0:5001")
    app.run(host='0.0.0.0', port=5001, debug=True)
