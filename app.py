"""
Expense Splitter - Flask Application
A simple bill splitting app for groups with user authentication
"""
from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import sqlite3
from datetime import datetime
import os
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-here-change-in-production')
DATABASE = os.environ.get('DATABASE_URL', 'database.db')
def get_db():
    """Get database connection"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn
def login_required(f):
    """Decorator to require login for routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function
def admin_required(f):
    """Decorator to require admin role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        if session.get('role') != 'admin':
            flash('Access denied. Admin privileges required.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function
def init_db():
    """Initialize database with tables (idempotent)."""
    try:
        conn = get_db()
        cursor = conn.cursor()
        print("Database initialization started...")
        
        # Users table for authentication
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT DEFAULT 'user',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create default admin user if not exists
        cursor.execute('SELECT COUNT(*) FROM users WHERE role = "admin"')
        admin_count = cursor.fetchone()[0]
        if admin_count == 0:
            admin_hash = generate_password_hash('admin123')
            cursor.execute('''
                INSERT INTO users (username, email, password_hash, role)
                VALUES (?, ?, ?, ?)
            ''', ('admin', 'admin@expensesplitter.com', admin_hash, 'admin'))
            conn.commit()
        
        # Groups table - add user_id to track ownership
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS groups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT,
                user_id INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        ''')
        
        # Members table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS members (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT,
                group_id INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE
            )
        ''')
        
        # Expenses table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS expenses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                group_id INTEGER,
                description TEXT NOT NULL,
                amount REAL NOT NULL,
                paid_by INTEGER,
                split_type TEXT DEFAULT 'equal',
                date DATE DEFAULT CURRENT_DATE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE,
                FOREIGN KEY (paid_by) REFERENCES members(id)
            )
        ''')
        
        # Expense splits table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS expense_splits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                expense_id INTEGER,
                member_id INTEGER,
                share_amount REAL NOT NULL,
                FOREIGN KEY (expense_id) REFERENCES expenses(id) ON DELETE CASCADE,
                FOREIGN KEY (member_id) REFERENCES members(id)
            )
        ''')
        
        # Settlements table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS settlements (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                group_id INTEGER,
                from_member INTEGER,
                to_member INTEGER,
                amount REAL NOT NULL,
                settled_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE,
                FOREIGN KEY (from_member) REFERENCES members(id),
                FOREIGN KEY (to_member) REFERENCES members(id)
            )
        ''')
        
        conn.commit()
        conn.close()
        print("Database initialization completed successfully!")
    except Exception as e:
        print(f"Database initialization error: {e}")
        conn.close()
        raise e

def calculate_balances(group_id):
    """Calculate who owes whom in a group"""
    conn = get_db()
    cursor = conn.cursor()
    
    # Get all members
    members = cursor.execute(
        'SELECT * FROM members WHERE group_id = ?', (group_id,)
    ).fetchall()
    
    balances = {}
    
    for member in members:
        # Total paid
        paid = cursor.execute(
            'SELECT COALESCE(SUM(amount), 0) FROM expenses WHERE group_id = ? AND paid_by = ?',
            (group_id, member['id'])
        ).fetchone()[0]
        
        # Total owed (share)
        owed = cursor.execute(
            'SELECT COALESCE(SUM(share_amount), 0) FROM expense_splits WHERE member_id = ?',
            (member['id'],)
        ).fetchone()[0]
        
        # Settlements received
        received = cursor.execute(
            'SELECT COALESCE(SUM(amount), 0) FROM settlements WHERE to_member = ?',
            (member['id'],)
        ).fetchone()[0]
        
        # Settlements given
        given = cursor.execute(
            'SELECT COALESCE(SUM(amount), 0) FROM settlements WHERE from_member = ?',
            (member['id'],)
        ).fetchone()[0]
        
        balance = (paid or 0) - (owed or 0) + (received or 0) - (given or 0)
        balances[member['id']] = {
            'name': member['name'],
            'balance': round(balance, 2),
            'paid': round(paid or 0, 2),
            'owed': round(owed or 0, 2)
        }
    
    conn.close()
    return balances
@app.route('/health')
def health():
    return {'status': 'ok'}
@app.route('/')
@login_required
def index():
    """Homepage - show all groups and quick split form"""
    conn = get_db()
    cursor = conn.cursor()
    
    # Only show groups belonging to the logged-in user
    groups = cursor.execute('''
        SELECT g.*, 
               COUNT(DISTINCT m.id) as member_count,
               COALESCE(SUM(e.amount), 0) as total_expenses
        FROM groups g
        LEFT JOIN members m ON g.id = m.group_id
        LEFT JOIN expenses e ON g.id = e.group_id
        WHERE g.user_id = ?
        GROUP BY g.id
        ORDER BY g.created_at DESC
    ''', (session['user_id'],)).fetchall()
    
    conn.close()
    return render_template('index.html', groups=groups)
@app.route('/submit', methods=['POST'])
@login_required
def quick_split_submit():
    """Handle quick split form from home page and show result on /success."""
    amount = request.form.get('qs_amount')
    people = request.form.get('qs_people')
    try:
        amount_f = float(amount)
        people_i = int(people)
        if amount_f <= 0 or people_i <= 0:
            raise ValueError
        per_person = round(amount_f / people_i, 2)
        return redirect(url_for('success', msg=f'₹{amount_f:.2f} split among {people_i} people = ₹{per_person:.2f} each'))
    except Exception:
        flash('Please enter a positive amount and number of people.', 'danger')
        return redirect(url_for('index'))
@app.route('/success')
@login_required
def success():
    msg = request.args.get('msg', 'Action completed successfully!')
    return render_template('success.html', message=msg)
@app.route('/about')
def about():
    """About page"""
    return render_template('about.html')
@app.route('/how-it-works')
def how_it_works():
    """How it works page"""
    return render_template('how_it_works.html')
@app.route('/help')
def help_page():
    """Help and FAQ page"""
    return render_template('help.html')
@app.route('/groups/create', methods=['GET', 'POST'])
@login_required
def create_group():
    """Create a new group"""
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description', '')
        member_names = request.form.getlist('members[]')
        
        # Validate
        if not name:
            flash('Group name is required!', 'danger')
            return redirect(url_for('create_group'))
        
        # Filter empty member names
        member_names = [m.strip() for m in member_names if m.strip()]
        
        if len(member_names) < 2:
            flash('At least 2 members are required!', 'danger')
            return redirect(url_for('create_group'))
        
        # Insert group with user_id
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO groups (name, description, user_id) VALUES (?, ?, ?)',
            (name, description, session['user_id'])
        )
        group_id = cursor.lastrowid
        
        # Insert members
        for member_name in member_names:
            cursor.execute(
                'INSERT INTO members (name, group_id) VALUES (?, ?)',
                (member_name, group_id)
            )
        
        conn.commit()
        conn.close()
        
        flash(f'Group "{name}" created successfully!', 'success')
        return redirect(url_for('group_detail', group_id=group_id))
    
    return render_template('groups/create_group.html')
@app.route('/groups/<int:group_id>')
@login_required
def group_detail(group_id):
    """Show group details, expenses, and balances"""
    conn = get_db()
    cursor = conn.cursor()
    
    # Get group
    group = cursor.execute('SELECT * FROM groups WHERE id = ?', (group_id,)).fetchone()
    if not group:
        flash('Group not found!', 'danger')
        return redirect(url_for('index'))
    
    # Get members
    members = cursor.execute(
        'SELECT * FROM members WHERE group_id = ? ORDER BY name',
        (group_id,)
    ).fetchall()
    
    # Get expenses
    expenses = cursor.execute('''
        SELECT e.*, m.name as paid_by_name
        FROM expenses e
        JOIN members m ON e.paid_by = m.id
        WHERE e.group_id = ?
        ORDER BY e.date DESC, e.created_at DESC
    ''', (group_id,)).fetchall()
    
    # Calculate balances
    balances = calculate_balances(group_id)
    
    # Get settlements
    settlements = cursor.execute('''
        SELECT s.*, m1.name as from_name, m2.name as to_name
        FROM settlements s
        JOIN members m1 ON s.from_member = m1.id
        JOIN members m2 ON s.to_member = m2.id
        WHERE s.group_id = ?
        ORDER BY s.settled_at DESC
    ''', (group_id,)).fetchall()
    
    conn.close()
    
    return render_template('groups/group_detail.html',
                         group=group,
                         members=members,
                         expenses=expenses,
                         balances=balances,
                         settlements=settlements)
@app.route('/groups/<int:group_id>/add_expense', methods=['GET', 'POST'])
@login_required
def add_expense(group_id):
    """Add expense to group"""
    conn = get_db()
    cursor = conn.cursor()
    
    # Get group and members
    group = cursor.execute('SELECT * FROM groups WHERE id = ?', (group_id,)).fetchone()
    members = cursor.execute('SELECT * FROM members WHERE group_id = ?', (group_id,)).fetchall()
    
    if not group:
        flash('Group not found!', 'danger')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        description = request.form.get('description')
        amount = request.form.get('amount')
        paid_by = request.form.get('paid_by')
        split_type = request.form.get('split_type', 'equal')
        
        # Validate
        if not all([description, amount, paid_by]):
            flash('All fields are required!', 'danger')
            return redirect(url_for('add_expense', group_id=group_id))
        
        try:
            amount = float(amount)
            paid_by = int(paid_by)
            if amount <= 0:
                raise ValueError
        except ValueError:
            flash('Invalid amount or payer!', 'danger')
            return redirect(url_for('add_expense', group_id=group_id))
        
        # Insert expense
        cursor.execute(
            'INSERT INTO expenses (group_id, description, amount, paid_by, split_type) VALUES (?, ?, ?, ?, ?)',
            (group_id, description, amount, paid_by, split_type)
        )
        expense_id = cursor.lastrowid
        
        # Calculate and insert splits
        if split_type == 'equal':
            share = round(amount / max(1, len(members)), 2)
            for member in members:
                cursor.execute(
                    'INSERT INTO expense_splits (expense_id, member_id, share_amount) VALUES (?, ?, ?)',
                    (expense_id, member['id'], share)
                )
        else:
            total_custom = 0.0
            for member in members:
                custom_share = request.form.get(f'share_{member["id"]}', '0')
                try:
                    custom_share_f = float(custom_share or 0)
                except ValueError:
                    custom_share_f = 0.0
                total_custom += custom_share_f
                cursor.execute(
                    'INSERT INTO expense_splits (expense_id, member_id, share_amount) VALUES (?, ?, ?)',
                    (expense_id, member['id'], custom_share_f)
                )
            # Validate sum equals amount (within small epsilon)
            if abs(total_custom - amount) > 0.01:
                # rollback this expense if split doesn't match
                conn.rollback()
                flash('Custom split must sum exactly to the total amount.', 'danger')
                conn.close()
                return redirect(url_for('add_expense', group_id=group_id))
        
        conn.commit()
        conn.close()
        
        flash('Expense added successfully!', 'success')
        return redirect(url_for('group_detail', group_id=group_id))
    
    conn.close()
    return render_template('expenses/add_expense.html', group=group, members=members)
@app.route('/groups/<int:group_id>/settle', methods=['GET', 'POST'])
@login_required
def settle_up(group_id):
    """Settle debts"""
    conn = get_db()
    cursor = conn.cursor()
    
    group = cursor.execute('SELECT * FROM groups WHERE id = ?', (group_id,)).fetchone()
    members = cursor.execute('SELECT * FROM members WHERE group_id = ?', (group_id,)).fetchall()
    balances = calculate_balances(group_id)
    
    if request.method == 'POST':
        from_member = request.form.get('from_member')
        to_member = request.form.get('to_member')
        amount = request.form.get('amount')
        
        try:
            from_member = int(from_member)
            to_member = int(to_member)
            amount = float(amount)
            if from_member == to_member or amount <= 0:
                raise ValueError
            cursor.execute(
                'INSERT INTO settlements (group_id, from_member, to_member, amount) VALUES (?, ?, ?, ?)',
                (group_id, from_member, to_member, amount)
            )
            conn.commit()
            
            flash('Settlement recorded successfully!', 'success')
            return redirect(url_for('group_detail', group_id=group_id))
        except Exception:
            flash('Invalid settlement data!', 'danger')
    
    conn.close()
    return render_template('settlements/settle_up.html', group=group, members=members, balances=balances)
@app.route('/expenses/<int:expense_id>/delete', methods=['POST'])
@login_required
def delete_expense(expense_id):
    """Delete an expense"""
    conn = get_db()
    cursor = conn.cursor()
    
    expense = cursor.execute('SELECT group_id FROM expenses WHERE id = ?', (expense_id,)).fetchone()
    if expense:
        cursor.execute('DELETE FROM expenses WHERE id = ?', (expense_id,))
        conn.commit()
        flash('Expense deleted!', 'success')
        conn.close()
        return redirect(url_for('group_detail', group_id=expense['group_id']))
    
    conn.close()
    flash('Expense not found!', 'danger')
    return redirect(url_for('index'))
@app.route('/groups/<int:group_id>/delete', methods=['POST'])
@login_required
def delete_group(group_id):
    """Delete a group"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM groups WHERE id = ?', (group_id,))
    conn.commit()
    conn.close()
    
    flash('Group deleted!', 'success')
    return redirect(url_for('index'))
@app.route('/members/<int:member_id>/delete', methods=['POST'])
@login_required
def delete_member(member_id):
    """Delete a member from a group"""
    conn = get_db()
    cursor = conn.cursor()
    
    # Get the group_id for this member
    member = cursor.execute('SELECT group_id FROM members WHERE id = ?', (member_id,)).fetchone()
    if not member:
        flash('Member not found!', 'danger')
        conn.close()
        return redirect(url_for('index'))
    
    group_id = member['group_id']
    
    # Delete the member (this will cascade to delete related expense_splits)
    cursor.execute('DELETE FROM members WHERE id = ?', (member_id,))
    conn.commit()
    conn.close()
    
    flash('Member removed successfully!', 'success')
    return redirect(url_for('group_detail', group_id=group_id))
@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login page"""
    if 'user_id' in session:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            flash('Please enter both username and password.', 'danger')
            return render_template('auth/login.html')
        
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            flash(f'Welcome back, {user["username"]}!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password.', 'danger')
    
    return render_template('auth/login.html')
@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration page"""
    if 'user_id' in session:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Validation
        if not all([username, email, password, confirm_password]):
            flash('All fields are required.', 'danger')
            return render_template('auth/register.html')
        
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('auth/register.html')
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'danger')
            return render_template('auth/register.html')
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Check if username or email already exists
        existing_user = cursor.execute('SELECT * FROM users WHERE username = ? OR email = ?', (username, email)).fetchone()
        if existing_user:
            flash('Username or email already exists.', 'danger')
            conn.close()
            return render_template('auth/register.html')
        
        # Create new user
        password_hash = generate_password_hash(password)
        cursor.execute('''
            INSERT INTO users (username, email, password_hash, role)
            VALUES (?, ?, ?, ?)
        ''', (username, email, password_hash, 'user'))
        conn.commit()
        conn.close()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('auth/register.html')
@app.route('/logout')
def logout():
    """Log out user"""
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))
@app.route('/admin')
@admin_required
def admin_dashboard():
    """Admin dashboard for user management"""
    conn = get_db()
    users = conn.execute('SELECT * FROM users ORDER BY created_at DESC').fetchall()
    
    # Get statistics
    stats = {
        'total_users': conn.execute('SELECT COUNT(*) FROM users').fetchone()[0],
        'total_groups': conn.execute('SELECT COUNT(*) FROM groups').fetchone()[0],
        'total_expenses': conn.execute('SELECT COUNT(*) FROM expenses').fetchone()[0],
        'admin_users': conn.execute('SELECT COUNT(*) FROM users WHERE role = "admin"').fetchone()[0]
    }
    
    conn.close()
    return render_template('auth/admin.html', users=users, stats=stats)
@app.route('/admin/users/<int:user_id>/toggle-role', methods=['POST'])
@admin_required
def toggle_user_role(user_id):
    """Toggle user role between user and admin"""
    if user_id == session.get('user_id'):
        flash('You cannot change your own role.', 'warning')
        return redirect(url_for('admin_dashboard'))
    
    conn = get_db()
    cursor = conn.cursor()
    
    user = cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    if user:
        new_role = 'admin' if user['role'] == 'user' else 'user'
        cursor.execute('UPDATE users SET role = ? WHERE id = ?', (new_role, user_id))
        conn.commit()
        flash(f'User role updated to {new_role}.', 'success')
    
    conn.close()
    return redirect(url_for('admin_dashboard'))
@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@admin_required
def delete_user(user_id):
    """Delete a user (admin only)"""
    if user_id == session.get('user_id'):
        flash('You cannot delete your own account.', 'warning')
        return redirect(url_for('admin_dashboard'))
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    
    flash('User deleted successfully.', 'success')
    return redirect(url_for('admin_dashboard'))

# Initialize database (idempotent) - runs on every startup
init_db()

if __name__ == '__main__':
    app.run(debug=True)
