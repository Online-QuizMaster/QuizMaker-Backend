from flask import Flask, request, jsonify
from flask_pymongo import PyMongo
from flask_cors import CORS
import re
import jwt
import datetime
import bcrypt
from bson import ObjectId

app = Flask(__name__)

app.config["MONGO_URI"] = "mongodb://localhost:27017/quizmaker"
app.config["SECRET_KEY"] = "your_secret_key" 

mongo = PyMongo(app)
CORS(app, resources={r"/api/*": {"origins": "http://localhost:3000"}}, supports_credentials=True)

def generate_token(_id,full_name, user_type):
    payload = {
        "userid": _id,  
        "fullName": full_name,
        "userType": user_type
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
        user_type = data.get('userType', 'student')  

        if not full_name or not email or not password:
            return jsonify({"message": "All fields are required"}), 400

        email_regex = r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
        if not re.match(email_regex, email):
            return jsonify({"message": "Invalid email format"}), 400

        if user_type not in ['student', 'teacher']:
            return jsonify({"message": "Invalid user type"}), 400

        existing_user = mongo.db.users.find_one({"email": email})
        if existing_user:
            return jsonify({"message": "Email already exists"}), 400

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        user = {
            "fullName": full_name,
            "email": email,
            "password": hashed_password,
            "userType": user_type
        }

        if user_type == 'student':
            user['quizComplete'] = []

        mongo.db.users.insert_one(user)

        return jsonify({
            "message": "Account created successfully",
            "user": full_name,
            "userType": user_type
        }), 201

    except Exception as e:
        print(f"Error in signup: {str(e)}")
        return jsonify({"message": f"Server error: {str(e)}"}), 500


@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            return jsonify({"message": "Email and password are required"}), 400

        user = mongo.db.users.find_one({"email": email})
        
        if not user:
            return jsonify({"message": "Invalid email or password"}), 401
        
        if not bcrypt.checkpw(password.encode('utf-8'), user['password']):
            return jsonify({"message": "Invalid email or password"}), 401

        user_id = str(user['_id']) 
        token = generate_token(user_id, user['fullName'], user['userType']) 
        
        return jsonify({
            "message": "Login successful",
            "token": token,
            "name": user['fullName'],
            "userType": user['userType'],
        }), 200
    except Exception as e:
        print(f"Error in login: {str(e)}")
        return jsonify({"message": f"Server error: {str(e)}"}), 500


@app.route('/api/protected', methods=['GET'])
def protected():
    token = request.headers.get('Authorization')

    if not token:
        return jsonify({"message": "Token is missing"}), 403

    try:
        token = token.split(" ")[1]
        decoded = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        user_id = decoded["user_id"]
    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token has expired"}), 403
    except jwt.InvalidTokenError:
        return jsonify({"message": "Invalid token"}), 403

    user = mongo.db.users.find_one({"_id": ObjectId(user_id)})
    if not user:
        return jsonify({"message": "User not found"}), 404

    return jsonify({
        "message": "Welcome to the protected route",
        "user": user['fullName']
    }), 200

@app.route('/api/create-quiz', methods=['POST', 'OPTIONS'])
def create_quiz():
    if request.method == 'OPTIONS':
        return jsonify({'message': 'CORS preflight success'}), 200

    try:
        token = request.headers.get('Authorization').split(" ")[1] if request.headers.get('Authorization') else None
        if not token:
            return jsonify({"message": "Token is missing"}), 401

        data = request.get_json()
        quiz_title = data.get('title')
        quiz_description = data.get('description')
        questions = data.get('questions')
        teacher_id = data.get('teacherId')  
        if not quiz_title or not quiz_description or not questions:
            return jsonify({"message": "All fields are required"}), 400

        for q in questions:
            if not q.get('questionText') or not q.get('options') or q.get('correctAnswer') is None:
                return jsonify({"message": "Invalid question format"}), 400

        quiz = {
            "title": quiz_title,
            "description": quiz_description,
            "questions": questions,
            "created_at": datetime.datetime.utcnow(),
            "teacherId": teacher_id  
        }

        result = mongo.db.quizzes.insert_one(quiz)

        return jsonify({
            "message": "Quiz created successfully",
            "quiz_id": str(result.inserted_id)
        }), 201

    except Exception as e:
        print(f"Error in create_quiz: {str(e)}")
        return jsonify({"message": f"Server error: {str(e)}"}), 500

    

@app.route('/api/get-all-quizzes', methods=['GET'])
def get_all_quizzes():
    try:
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 10))
        search_term = request.args.get('search', '')

        query = {}
        if search_term:
            query['$or'] = [
                {'title': {'$regex': search_term, '$options': 'i'}},
                {'description': {'$regex': search_term, '$options': 'i'}}
            ]

        total = mongo.db.quizzes.count_documents(query)
        quizzes = mongo.db.quizzes.find(query).skip((page - 1) * per_page).limit(per_page)

        quiz_list = []
        for quiz in quizzes:
            quiz['_id'] = str(quiz['_id']) 
            quiz_list.append({
                '_id': quiz['_id'],
                'title': quiz.get('title'),
                'description': quiz.get('description'),
                'imageUrl': quiz.get('imageUrl'),
                'difficulty': quiz.get('difficulty'),
                'questionCount': len(quiz.get('questions', [])),
                'teacherId': str(quiz.get('teacherId'))  
            })

        return jsonify({
            'quizzes': quiz_list,
            'total': total,
            'page': page,
            'per_page': per_page
        }), 200

    except Exception as e:
        app.logger.error(f"Error in get_all_quizzes: {str(e)}")
        return jsonify({
            "message": "Unable to fetch quizzes",
            "error": str(e)
        }), 500


@app.route('/api/get-quiz/<quiz_id>', methods=['GET'])
def get_quiz(quiz_id):
    try:
        quiz = mongo.db.quizzes.find_one({"_id": ObjectId(quiz_id)})

        if not quiz:
            return jsonify({"message": "Quiz not found"}), 404
        
        quiz['_id'] = str(quiz['_id'])

        return jsonify(quiz), 200

    except Exception as e:
        print(f"Error in get_quiz: {str(e)}")
        return jsonify({"message": f"Server error: {str(e)}"}), 500

from bson import ObjectId

@app.route('/api/mark-quiz-complete', methods=['POST'])
def mark_quiz_complete():
    try:
        data = request.get_json()
        user_id = data.get('_id')
        quiz_id = data.get('quizId')
        marks = data.get('marks')

        if not user_id or not quiz_id or marks is None:
            return jsonify({"message": "Missing _id, quizId, or marks"}), 400

        try:
            object_id = ObjectId(user_id)
        except Exception:
            return jsonify({"message": "Invalid user ID format"}), 400

        user = mongo.db.users.find_one({"_id": object_id})
        if not user:
            return jsonify({"message": "User not found"}), 404

        if user.get('userType') != 'student':
            return jsonify({"message": "Only students can complete quizzes"}), 403

        quiz_entry = {"quizId": quiz_id, "marks": marks}

        mongo.db.users.update_one(
            {"_id": object_id},
            {"$addToSet": {"quizComplete": quiz_entry}}
        )

        return jsonify({"message": "Quiz marked as complete with marks"}), 200

    except Exception as e:
        print(f"Error in mark_quiz_complete: {str(e)}")
        return jsonify({"message": f"Server error: {str(e)}"}), 500

@app.route('/api/user-stats/<user_id>', methods=['GET'])
def user_stats(user_id):
    try:
        object_id = ObjectId(user_id)
        user = mongo.db.users.find_one({"_id": object_id})
        if not user:
            return jsonify({"message": "User not found"}), 404

        completed = user.get("quizComplete", [])  
        enriched_results = []
        total_marks = 0

        for entry in completed:
            quiz = mongo.db.quizzes.find_one({"_id": ObjectId(entry["quizId"])})
            quiz_name = quiz.get("title", "Untitled Quiz") if quiz else "Unknown Quiz"
            mark = entry.get("marks", 0)
            total_marks += mark
            enriched_results.append({
                "quizId": entry["quizId"],
                "quizName": quiz_name,
                "mark": mark
            })

        average = total_marks / len(enriched_results) if enriched_results else 0

        return jsonify({"completed": enriched_results, "average": average})
    except Exception as e:
        return jsonify({"message": f"Server error: {str(e)}"}), 500


@app.route('/api/teacher-results/<teacher_id>', methods=['GET'])
def teacher_results(teacher_id):
    try:
        teacher_quizzes = list(mongo.db.quizzes.find({"teacherId": teacher_id}))
        quiz_id_title_map = {str(quiz["_id"]): quiz["title"] for quiz in teacher_quizzes}

        # If no quizzes found
        if not quiz_id_title_map:
            return jsonify([]), 200

        quiz_ids = list(quiz_id_title_map.keys())

        students = mongo.db.users.find({
            "userType": "student",
            "quizComplete": {
                "$elemMatch": {
                    "quizId": {"$in": quiz_ids}
                }
            }
        })

        results = []

        for student in students:
            full_name = student.get("fullName", "Unknown Student")
            quiz_completions = student.get("quizComplete", [])

            for entry in quiz_completions:
                quiz_id = entry.get("quizId")
                if quiz_id in quiz_id_title_map:
                    results.append({
                        "studentName": full_name,
                        "quizName": quiz_id_title_map[quiz_id],
                        "mark": entry.get("marks", 0)
                    })

        return jsonify(results), 200

    except Exception as e:
        print(f"Error in /api/teacher-results: {str(e)}")
        return jsonify({"message": f"Server error: {str(e)}"}), 500


@app.route('/api/delete-quiz/<quiz_id>', methods=['DELETE'])
def delete_quiz(quiz_id):
    try:
        result = mongo.db.quizzes.delete_one({"_id": ObjectId(quiz_id)})

        if result.deleted_count == 0:
            return jsonify({"message": "Quiz not found"}), 404

        return jsonify({"message": "Quiz deleted successfully"}), 200

    except Exception as e:
        print(f"Error in delete_quiz: {str(e)}")
        return jsonify({"message": f"Server error: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(debug=True)
