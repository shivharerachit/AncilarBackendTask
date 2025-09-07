from flask import Flask, request, jsonify, g
from werkzeug.security import generate_password_hash, check_password_hash
from email_validator import validate_email, EmailNotValidError
import os
from dotenv import load_dotenv
import sqlite3

load_dotenv()

app = Flask(__name__)

DATABASE = '/Users/rachitshivhare/Code/AncilarBackendTask/CaseInsensitiveLogin/database.db'

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db


@app.route("/signup", methods=["POST"])
def signup():
    cur = get_db().cursor()
    data = request.json
    username = data.get("username", "").lower()
    email = data.get("email", "")
    password = data.get("password", "")
    hashed_password = generate_password_hash(password)

    fetchUsername = cur.execute("SELECT * FROM users WHERE username=? ", (username,))
    fetchUsername = cur.fetchall()
    fetchEmail = cur.execute("SELECT * FROM users WHERE email=? ", (email,))
    fetchEmail = cur.fetchall()
    print(fetchEmail)

    if(int(len(fetchUsername)) > 0):
        return jsonify({"Error": "Username already exists"})
    
    if(int(len(fetchEmail)) > 0):
        return jsonify({"Error": "Email already exists"})
    
    try:
        emailinfo = validate_email(email, check_deliverability=False)
        email = emailinfo.normalized
        cur.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                    (username, email, hashed_password,))
        get_db().commit()
        id = cur.execute("SELECT id FROM users WHERE username=?", (username,))
        id = cur.fetchone()
        return jsonify({"Success": "User registered successfully", "id": id})
    except EmailNotValidError as e:
        print(str(e))
        return jsonify({"error": str(e)})
    except Exception as e:
        return jsonify({"Error": f"An Error Occurred: {str(e)}"})

@app.route("/login", methods=["POST"])
def login():
    cur = get_db().cursor()
    data = request.json
    username = data.get("username", "").lower()
    password = data.get("password", "")

    try:
        user = cur.execute("SELECT * FROM users WHERE username=?", (username,))
        user = user.fetchone()
        if user and check_password_hash(user[3], password): 
            return jsonify({"message": "Login successful"}), 200
        return jsonify({"ERROR": "Invalid username or password"}), 401
    except Exception as e:
        return jsonify({"ERROR": f"An Error occurred: {str(e)}"}), 500



@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


if __name__ == "__main__":
    app.run(debug=True)