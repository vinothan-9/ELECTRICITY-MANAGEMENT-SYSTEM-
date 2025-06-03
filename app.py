from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import sqlite3
from datetime import datetime, timedelta
import hashlib
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Database connection
def get_db_connection():
    conn = sqlite3.connect('electricity_bills.db')
    conn.row_factory = sqlite3.Row
    return conn

# Initialize database
def init_db():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL,
        name TEXT,
        email TEXT,
        address TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS customers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        meter_number TEXT UNIQUE,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS tariffs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        slab INTEGER,
        rate REAL,
        effective_date TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS meter_readings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        customer_id INTEGER,
        reading_date TEXT,
        units INTEGER,
        FOREIGN KEY (customer_id) REFERENCES customers(id)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS bills (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        customer_id INTEGER,
        bill_date TEXT,
        due_date TEXT,
        amount REAL,
        status TEXT,
        units INTEGER,
        FOREIGN KEY (customer_id) REFERENCES customers(id)
    )''')
    conn.commit()
    conn.close()

@app.route('/')
def index():
    if 'user_id' in session:
        if session['role'] == 'admin':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('user_dashboard'))
    return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['role'] = user['role']
            if user['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('user_dashboard'))
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        name = request.form['name']
        email = request.form['email']
        address = request.form['address']
        meter_number = request.form['meter_number']
        
        conn = get_db_connection()
        try:
            c = conn.cursor()
            c.execute('INSERT INTO users (username, password, role, name, email, address) VALUES (?, ?, ?, ?, ?, ?)',
                     (username, password, 'customer', name, email, address))
            user_id = c.lastrowid
            c.execute('INSERT INTO customers (user_id, meter_number) VALUES (?, ?)',
                     (user_id, meter_number))
            conn.commit()
            flash('Registration successful! Please login.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username or meter number already exists')
        finally:
            conn.close()
    return render_template('register.html')

@app.route('/user_dashboard')
def user_dashboard():
    if 'user_id' not in session or session['role'] != 'customer':
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    customer = conn.execute('SELECT * FROM customers WHERE user_id = ?', (session['user_id'],)).fetchone()
    bills = conn.execute('SELECT * FROM bills WHERE customer_id = ? ORDER BY bill_date DESC', (customer['id'],)).fetchall()
    readings = conn.execute('SELECT * FROM meter_readings WHERE customer_id = ? ORDER BY reading_date DESC', (customer['id'],)).fetchall()
    conn.close()
    
    return render_template('user_dashboard.html', bills=bills, readings=readings)

@app.route('/pay_bill/<int:bill_id>', methods=['POST'])
def pay_bill(bill_id):
    if 'user_id' not in session or session['role'] != 'customer':
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    conn.execute('UPDATE bills SET status = ? WHERE id = ?', ('Paid', bill_id))
    conn.commit()
    conn.close()
    flash('Bill paid successfully')
    return redirect(url_for('user_dashboard'))

@app.route('/usage_report')
def usage_report():
    if 'user_id' not in session or session['role'] != 'customer':
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    customer = conn.execute('SELECT * FROM customers WHERE user_id = ?', (session['user_id'],)).fetchone()
    readings = conn.execute('SELECT * FROM meter_readings WHERE customer_id = ? ORDER BY reading_date', (customer['id'],)).fetchall()
    conn.close()
    
    return render_template('usage_report.html', readings=readings)

@app.route('/admin_dashboard')
def admin_dashboard():
    if 'user_id' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    customers = conn.execute('SELECT c.*, u.name, u.email FROM customers c JOIN users u ON c.user_id = u.id').fetchall()
    tariffs = conn.execute('SELECT * FROM tariffs ORDER BY effective_date DESC').fetchall()
    conn.close()
    
    return render_template('admin_dashboard.html', customers=customers, tariffs=tariffs)

@app.route('/add_reading', methods=['POST'])
def add_reading():
    if 'user_id' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    
    customer_id = request.form['customer_id']
    units = int(request.form['units'])
    reading_date = datetime.now().strftime('%Y-%m-%d')
    
    conn = get_db_connection()
    conn.execute('INSERT INTO meter_readings (customer_id, reading_date, units) VALUES (?, ?, ?)',
                (customer_id, reading_date, units))
    
    # Calculate bill
    tariffs = conn.execute('SELECT * FROM tariffs ORDER BY slab').fetchall()
    amount = 0
    remaining_units = units
    
    for tariff in tariffs:
        if remaining_units > 0:
            slab_units = min(remaining_units, tariff['slab'])
            amount += slab_units * tariff['rate']
            remaining_units -= slab_units
    
    bill_date = datetime.now().strftime('%Y-%m-%d')
    due_date = (datetime.now() + timedelta(days=15)).strftime('%Y-%m-%d')
    
    conn.execute('INSERT INTO bills (customer_id, bill_date, due_date, amount, status, units) VALUES (?, ?, ?, ?, ?, ?)',
                (customer_id, bill_date, due_date, amount, 'Pending', units))
    
    conn.commit()
    conn.close()
    flash('Reading added and bill generated')
    return redirect(url_for('admin_dashboard'))

@app.route('/update_tariff', methods=['POST'])
def update_tariff():
    if 'user_id' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    
    slab = int(request.form['slab'])
    rate = float(request.form['rate'])
    effective_date = datetime.now().strftime('%Y-%m-%d')
    
    conn = get_db_connection()
    conn.execute('INSERT INTO tariffs (slab, rate, effective_date) VALUES (?, ?, ?)',
                (slab, rate, effective_date))
    conn.commit()
    conn.close()
    flash('Tariff updated')
    return redirect(url_for('admin_dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()
    # Create default admin user
    conn = get_db_connection()
    try:
        conn.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
                    ('admin', generate_password_hash('admin123'), 'admin'))
        conn.commit()
    except sqlite3.IntegrityError:
        pass
    conn.close()
    app.run(debug=True)