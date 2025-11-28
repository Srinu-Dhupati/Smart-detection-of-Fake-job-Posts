import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row  # This allows accessing columns by name
    return conn

def init_db():
    """Initialize the database and create tables"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL
        )
    ''')
    
    conn.commit()
    conn.close()

def register_user(username, password, email):
    """Register a new user"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Hash the password before storing
        hashed_password = generate_password_hash(password)
        
        cursor.execute(
            'INSERT INTO users (username, password, email) VALUES (?, ?, ?)',
            (username, hashed_password, email)
        )
        
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        return False  # Username or email already exists
    except Exception as e:
        print(f"Error registering user: {e}")
        return False

def get_user(username, password):
    """Authenticate user and return user data"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get user by username
        user = cursor.execute(
            'SELECT id, username, password FROM users WHERE username = ?',
            (username,)
        ).fetchone()
        
        conn.close()

        # Check if user exists and password is correct
        if user and check_password_hash(user['password'], password):
            return (user['id'], user['username'])  # Return tuple as expected by application.py
        return None
        
    except Exception as e:
        print(f"Error getting user: {e}")
        return None

# Initialize database when module is imported
init_db()