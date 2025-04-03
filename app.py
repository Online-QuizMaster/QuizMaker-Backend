from flask import Flask, request, jsonify
from flask_pymongo import PyMongo
from flask_cors import CORS
import re
import jwt
import datetime
import bcrypt
from bson import ObjectId

app = Flask(__name__)

# Enable CORS for all routes
CORS(app)

# Config for MongoDB connection
app.config["MONGO_URI"] = "mongodb://localhost:27017/quizmaker"  # Replace with your MongoDB URI if needed
app.config["SECRET_KEY"] = "your_secret_key"  # Change this to a strong secret key

mongo = PyMongo(app)

def generate_token(user_id):
    payload = {
        "user_id": str(user_id),
        "exp": datetime.datetime.utcnow() + datetime.timedelta(days=1)  # Token expires in 1 day
    }
    token = jwt.encode(payload, app.config["SECRET_KEY"], algorithm="HS256")
    return token

@app.route('/api/signup', methods=['POST'])
def signup():
    try:
        data = request.get_json()
        full_name = data.get('fullName')
        email = data.get('email')
        password = data.get('password')

        if not full_name or not email or not password:
            return jsonify({"message": "All fields are required"}), 400

        email_regex = r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
        if not re.match(email_regex, email):
            return jsonify({"message": "Invalid email format"}), 400

        existing_user = mongo.db.users.find_one({"email": email})
        if existing_user:
            return jsonify({"message": "Email already exists"}), 400

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        user = {"fullName": full_name, "email": email, "password": hashed_password}
        mongo.db.users.insert_one(user)

        return jsonify({"message": "Account created successfully", "user": full_name}), 201
    except Exception as e:
        print(f"Error: {str(e)}")  
        return jsonify({"message": f"Server error: {str(e)}"}), 500

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"message": "Email and password are required"}), 400

    # Find the user by email
    user = mongo.db.users.find_one({"email": email})
    if not user or not bcrypt.checkpw(password.encode('utf-8'), user['password']):
        return jsonify({"message": "Invalid email or password"}), 401

    # Generate JWT token
    token = generate_token(user['_id'])

    return jsonify({"message": "Login successful", "token": token}), 200

# Protected route to demonstrate JWT usage
@app.route('/api/protected', methods=['GET'])
def protected():
    token = request.headers.get('Authorization')

    if not token:
        return jsonify({"message": "Token is missing"}), 403

    try:
        # Decode the token
        token = token.split(" ")[1]  # Extract token from 'Bearer <token>'
        decoded = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        user_id = decoded["user_id"]
    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token has expired"}), 403
    except jwt.InvalidTokenError:
        return jsonify({"message": "Invalid token"}), 403

    # Fetch the user from the database
    user = mongo.db.users.find_one({"_id": ObjectId(user_id)})
    if not user:
        return jsonify({"message": "User not found"}), 404

    return jsonify({"message": "Welcome to the protected route", "user": user['fullName']}), 200

if __name__ == '__main__':
    app.run(debug=True)
