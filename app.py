from flask import Flask, render_template, request, redirect, url_for, session, g, make_response
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash # 1-Security Feature (Hashed Password)
from datetime import timedelta # 2-Security Feature (Session Timeout)

app = Flask(__name__)
app.secret_key = "supersecretkey"# To manage sessions (required by Flask)

DATABASE = 'members.db'

# Username & Password
# admin     |   admin123    |   staff
# staff     |   staffpass   |   staff
# pakkarim  |   karim       |   staff
# member    |   memberpass  |   member
# haiqal    |   haiqal123   |   member

# Set session timeout to 1 minutes
app.permanent_session_lifetime = timedelta(minutes=1)

@app.before_request
def session_check():
    session.permanent = True
    if request.endpoint not in ['login', 'register', 'static']:  # Allow access to login/register
        if 'user' not in session:
            return redirect(url_for('login'))
    
# Helper function to connect to the SQLite database
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # Enable dictionary-like row access
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()
        
def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv
    
@app.before_request
def create_tables():
    db = get_db()
    # Table classes
    db.execute('''CREATE TABLE IF NOT EXISTS classes (
                    id INTEGER PRIMARY KEY,
                    class_name TEXT NOT NULL,
                    class_time TEXT NOT NULL
                )''')
    # Table members_classes
    db.execute('''CREATE TABLE IF NOT EXISTS member_classes (
                    member_id INTEGER,
                    class_id INTEGER,
                    FOREIGN KEY (member_id) REFERENCES members (id),
                    FOREIGN KEY (class_id) REFERENCES classes (id)
                )''')
    # Table users
    db.execute('''CREATE TABLE IF NOT EXISTS users ( 
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL
                )''')
    db.commit()

# Login with hashed password verification
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        if user and check_password_hash(user['password'], password):
            session['user'] = username
            session['user_id'] = user['id']  # Store member ID
            session['role'] = user['role']

            return redirect(url_for('dashboard'))
        else:
            return "Login Failed! Incorrect Username or Password."

    return render_template('login.html')
    
# Register a new user with hashed password
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']  # Get role from form
        hashed_password = generate_password_hash(password)

        db = get_db()
        try:
            db.execute("INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)",
                       (username, email, hashed_password, role))
            db.commit()
            return redirect(url_for('login'))  # Redirect to login after success
        except sqlite3.IntegrityError:
            return "Error: Username or Email already exists."

    return render_template('register.html')
    
# Dashboard route
@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))

    role = session.get('role')  # Get user role from session
    return render_template('dashboard.html', username=session['user'], role=role)

@app.after_request
def add_no_cache_headers(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

#veiw specific member class
@app.route('/member/<int:member_id>/classes')
def member_classes(member_id):
    if 'user' not in session:
        return redirect(url_for('login'))

    # Check if the member exists
    member = query_db("SELECT * FROM users WHERE id = ?", [member_id], one=True)
    if not member:
        return "Member not found!", 404  # Return a 404 error if member doesn't exist

    # Get classes assigned to this member
    classes = query_db("SELECT c.class_name, c.class_time FROM classes c "
                        "JOIN member_classes mc ON c.id = mc.class_id "
                        "WHERE mc.member_id = ?", [member_id])

    return render_template('member_classes.html', member=member, classes=classes)

#register class
@app.route('/register_class/<int:member_id>', methods=['GET', 'POST'])
def register_class(member_id):
    if 'user' not in session or session['role'] != 'member':
        return "Access Denied! Only members can register for classes.", 403  # Block staff from registering

    db = get_db()
    classes = db.execute("SELECT * FROM classes").fetchall()

    if request.method == 'POST':
        class_id = request.form['class_id']
        db.execute("INSERT INTO member_classes (member_id, class_id) VALUES (?, ?)", (member_id, class_id))
        db.commit()
        return redirect(url_for('dashboard'))

    return render_template('register_class.html', member_id=member_id, classes=classes)

#view users
@app.route('/view_members')
def view_members():
    if 'user' not in session or session.get('role') != 'staff':
        return "Access Denied! Only staff can view members.", 403

    db = get_db()
    members = db.execute("SELECT * FROM users").fetchall()
    return render_template('view_members.html', members=members)

# New Route for Registering a Member
@app.route('/register_member', methods=['GET', 'POST'])
def register_member():
    if 'user' not in session or session['role'] != 'staff':
        return "Access Denied! Only staff can view members.", 403
        
    if request.method == 'POST':
        name = request.form['name']
        status = request.form['status']
        db = get_db()
        db.execute("INSERT INTO members (name, membership_status) VALUES (?,?)", (name, status))
        db.commit()
        return redirect(url_for('view_members'))
        
    return render_template('register_member.html')

# Class Scheduling Routes
@app.route('/add_class', methods=['GET', 'POST'])
def add_class():
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        class_name = request.form['class_name']
        class_time = request.form['class_time']
        db = get_db()
        db.execute("INSERT INTO classes (class_name, class_time) VALUES (?,?)", (class_name, class_time))
        db.commit()
        return redirect(url_for('view_classes'))
    
    return render_template('add_class.html')
    
@app.route('/view_classes')
def view_classes():
    if 'user' not in session:
        return redirect(url_for('login'))

    role = session.get('role')  # Get role from session
    db = get_db()
    classes = db.execute("SELECT * FROM classes").fetchall()

    return render_template('view_classes.html', classes=classes, role=role)

# Register CLasses
@app.route('/my_classes/<int:member_id>')
def my_classes(member_id):
    if 'user' not in session or session['role'] != 'member':
        return "Access Denied! Only members can view their registered classes.", 403

    db = get_db()
    classes = db.execute("""
        SELECT c.id, c.class_name, c.class_time 
        FROM classes c
        JOIN member_classes mc ON c.id = mc.class_id
        WHERE mc.member_id = ?
    """, (member_id,)).fetchall()

    return render_template('my_classes.html', classes=classes, member_id=member_id)

# Edit classes
@app.route('/edit_class/<int:class_id>', methods=['GET', 'POST'])
def edit_class(class_id):
    if 'user' not in session or session['role'] != 'staff':
        return "Access Denied! Only staff can edit classes.", 403

    db = get_db()
    class_data = db.execute("SELECT * FROM classes WHERE id = ?", (class_id,)).fetchone()

    if not class_data:
        return "Error: Class not found.", 404

    if request.method == 'POST':
        new_name = request.form['class_name']
        new_time = request.form['class_time']
        db.execute("UPDATE classes SET class_name = ?, class_time = ? WHERE id = ?", (new_name, new_time, class_id))
        db.commit()
        return redirect(url_for('view_classes'))

    return render_template('edit_class.html', class_data=class_data)

# Delete classes
@app.route('/delete_class/<int:class_id>', methods=['POST'])
def delete_class_admin(class_id):  # Renamed to delete_class_admin
    if 'user' not in session or session['role'] != 'staff':
        return "Access Denied! Only staff can delete classes.", 403

    db = get_db()
    db.execute("DELETE FROM member_classes WHERE class_id = ?", (class_id,))
    db.execute("DELETE FROM classes WHERE id = ?", (class_id,))
    db.commit()
    return redirect(url_for('view_classes'))

# Deleting member
@app.route('/delete_member/<int:member_id>', methods=['POST'])
def delete_member(member_id):
    if 'user' not in session or session['role'] != 'staff':
        return "Access Denied! Only staff can delete members.", 403  # Prevent unauthorized deletion

    db = get_db()
    
    # Check if the user exists before deletion
    user = db.execute("SELECT * FROM users WHERE id = ?", (member_id,)).fetchone()
    if not user:
        return "Error: User not found.", 404  # Return error if user does not exist

    try:
        # Delete the user
        db.execute("DELETE FROM users WHERE id = ?", (member_id,))
        db.commit()
        return redirect(url_for('view_members'))  # Redirect back to the members list
    except sqlite3.Error as e:
        return f"Database Error: {e}", 500  # Handle potential database errors

# Deleting my_class
@app.route('/unregister_class/<int:member_id>/<int:class_id>', methods=['POST'])
def unregister_class(member_id, class_id):
    if 'user' not in session or session['role'] != 'member':
        return "Access Denied! Only members can unregister from classes.", 403

    db = get_db()
    db.execute("DELETE FROM member_classes WHERE member_id = ? AND class_id = ?", (member_id, class_id))
    db.commit()
    return redirect(url_for('my_classes', member_id=member_id))

# Logout
@app.route('/logout')
def logout():
    session.clear()  # Ensure full session reset
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)

