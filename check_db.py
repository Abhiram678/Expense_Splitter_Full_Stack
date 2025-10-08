import sqlite3

# Check database
conn = sqlite3.connect('database.db')
cursor = conn.cursor()

# Check tables
cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
tables = cursor.fetchall()
print("Tables:", [t[0] for t in tables])

# Check data
try:
    cursor.execute("SELECT COUNT(*) FROM users")
    users_count = cursor.fetchone()[0]
    print(f"Users: {users_count}")
    
    cursor.execute("SELECT COUNT(*) FROM groups")
    groups_count = cursor.fetchone()[0]
    print(f"Groups: {groups_count}")
    
    cursor.execute("SELECT COUNT(*) FROM members")
    members_count = cursor.fetchone()[0]
    print(f"Members: {members_count}")
    
    cursor.execute("SELECT COUNT(*) FROM expenses")
    expenses_count = cursor.fetchone()[0]
    print(f"Expenses: {expenses_count}")
    
except Exception as e:
    print(f"Error: {e}")

conn.close()
print("Database connection successful")
