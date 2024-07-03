from flask import Flask, jsonify, request, send_file, send_from_directory, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, joinedload,Mapped, mapped_column
from sqlalchemy import Integer, String, select
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
import os
from werkzeug.utils import secure_filename
from datetime import datetime as dt, timedelta as td

api = Flask(__name__, static_folder='media')
CORS(api)
api.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///library.db"
api.config['SECRET_KEY'] = 'your_secret_key_here'
api.config['JWT_SECRET_KEY'] = 'jwt_secret_key_here'

UPLOAD_FOLDER = os.path.join(os.getcwd(), 'media')
api.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

class Base(DeclarativeBase):
  pass

db = SQLAlchemy(model_class=Base)
jwt= JWTManager(api)

db.init_app(api)

class Books(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    bookName = db.Column(db.String, unique=True)
    bookAuthor = db.Column(db.String)
    bookPublished = db.Column(db.Integer)
    book_image_path = db.Column(db.String)
    loanType = db.Column(db.Integer)
    Active = db.Column(db.Boolean)

class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    Email = db.Column(db.String, unique=True)
    Password = db.Column(db.String)
    Role = db.Column(db.String)
    Active = db.Column(db.Boolean)


class Loans(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    UserID = db.Column(db.Integer, db.ForeignKey('users.id'))
    BookID = db.Column(db.Integer, db.ForeignKey('books.id'))
    loanDate = db.Column(db.Integer)
    returnDate = db.Column(db.Integer)
    Active = db.Column(db.Boolean)

    user = db.relationship('Users', backref='loans')
    book = db.relationship('Books', backref='loans')

# ADD ADMIN ROUTE, NO HTML REQUIRED ADDING ADMINS WILL BE DONE THRU THE BACKEND

@api.route('/registerAdmin', methods=['POST'])
def registerAdmin():
    data = request.get_json()
    if not data or not data.get('Email') or not data.get('Password'):
        return jsonify({"msg": "Missing email or password"}), 400

    Email = data['Email']
    password= data['Password']

    if Users.query.filter_by(Email=Email).first() is not None:
        return jsonify({"msg": "User already exists"}), 409

    pwd_hash = generate_password_hash(password)
    new_Admin = Users(Email=Email, Password=pwd_hash, Active=True, Role="Admin")
    db.session.add(new_Admin)
    db.session.commit()

    return jsonify({"msg": "User registered successfully"}), 201
# REGISTER FOR CLIENTS, HTML ADDED
@api.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data or not data.get('Email') or not data.get('Password'):
        return jsonify({"msg": "Missing email or password"}), 400

    Email = data['Email']
    password= data['Password']

    if Users.query.filter_by(Email=Email).first() is not None:
        return jsonify({"msg": "User already exists"}), 409

    pwd_hash = generate_password_hash(password)
    new_user = Users(Email=Email, Password=pwd_hash, Active=True, Role="client")
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"msg": "User registered successfully"}), 201
# LOGIN, HTML ADDED
@api.route('/', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        data = request.get_json()
        Email = data['Email']
        password = data['Password']

        user = Users.query.filter_by(Email=Email).first() or Users.query.filter_by(Role="Admin", Email=Email).first()
        
        if not user:
            return jsonify({
                'message': 'User not found'
            }), 401

        if user.Active == 0:
            return jsonify({"msg": "User has been set to inactive by admin"}), 403

        if not check_password_hash(user.Password, password):
            return jsonify({
                'message': 'Wrong password'
            }), 401

        acc_token = create_access_token(identity=user.Email, additional_claims={'role': user.Role})
        return jsonify({'acc_token': acc_token}), 200
    return send_file('../frontend/index.html')

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@api.route('/media/<path:filename>')  # Endpoint to serve media files
def media(filename):
    return send_from_directory(api.config['UPLOAD_FOLDER'], filename)
# ADD BOOK, HTML ADDED
@api.route('/addBook', methods=['POST'])
@jwt_required()
def add_book():
    logged_user = get_jwt_identity()['email']
    admin = Users.query.filter_by(Role='Admin').first()
    # print(logged_user)
    # print(admin)
    if logged_user == admin.Email:
        bookName = request.form['bookName']
        bookAuthor = request.form['bookAuthor']
        bookPublished = request.form['bookPublished']
        loanType = request.form['loanType']
        
        if Books.query.filter_by(bookName=bookName).first() is not None:
            return jsonify({"msg": "Book name already exists"}), 409

        file = request.files['bookImage']
        if file.filename == '':
            return jsonify({"msg": "No selected file"}), 400
        
        # Handle file upload
        if 'bookImage' not in request.files:
            return jsonify({"msg": "No file part"}), 400

        if file:
            filename = secure_filename(file.filename)
            file_path = os.path.join(api.config['UPLOAD_FOLDER'], filename)
            try:
                file.save(file_path)

                # Save the relative path to the database
                relative_file_path = os.path.relpath(file_path, api.config['UPLOAD_FOLDER'])

                new_book = Books(
                    bookName=bookName,
                    bookAuthor=bookAuthor,
                    bookPublished=bookPublished,
                    Active=True,
                    book_image_path=relative_file_path,  # Save the relative path in the database
                    loanType = loanType
                )
                db.session.add(new_book)
                db.session.commit()

                return jsonify({"msg": f'{bookName} successfully added'}), 201
            except Exception as e:
                return jsonify({"msg": f"File saving error: {str(e)}"}), 500
    else:
        return jsonify({"msg": "User does not have authority for this action"}), 403

#SHOW THE EXISTING BOOKS AVAILABLE, HTML ADDED
@api.route('/showBook', methods=['GET'])
def show_book():
    books = Books.query.filter_by(Active=True).all()
    book_list = []
    for book in books:
        book_data = {
            'id': book.id,
            'bookName': book.bookName,
            'bookAuthor': book.bookAuthor,
            'bookPublished': book.bookPublished,
            'book_image_path': url_for('media', filename=book.book_image_path) if book.book_image_path else None
        }
        book_list.append(book_data)
    return jsonify(book_list)


# SHOWS THE USERS AND THEIR LOAN ID'S, NO HTML
@api.route('/showUser', methods=['GET'])
@jwt_required()
def show_users():
    logged_user = get_jwt_identity()
    admin_emails = Users.query.filter_by(Role='Admin').first()
    if logged_user == admin_emails.Email:
        user_list = db.session.query(Users).options(joinedload(Users.loans)).all()
        users = [{
            "Email": user.Email,
            "Loans": [{"LoanID": loan.id} for loan in user.loans]
        } for user in user_list]
        return jsonify(users)
    else:
        return jsonify({"message": "Unauthorized"}), 401

        

@api.route('/delBook/<int:book_id>', methods=['DELETE'])
@jwt_required()
def del_book(book_id):
    logged_user = get_jwt_identity()
    admin_emails = Users.query.filter_by(Role='Admin').first()
    if logged_user == admin_emails.Email:
        book = db.session.execute(db.select(Books).filter_by(id=book_id)).scalars().first()
        if book:
            print(book_id)
            book.Active = 0
            db.session.commit()
    return "test"

@api.route('/loanBook/<int:book_id>', methods=['POST'])
@jwt_required()
def loan_book(book_id):
    logged_user = get_jwt_identity()
    user = Users.query.filter_by(Email=logged_user).first()

    if not user:
        return jsonify({"msg": "User not found"}), 404

    book = Books.query.filter_by(id=book_id).first()
    if not book:
        return jsonify({"msg": "Book not found"}), 404

    if not book.Active:
        return jsonify({"msg": "Book already loaned"}), 400

    loan = Loans.query.filter_by(BookID=book_id, UserID=user.id).first()
    if loan:
        loan.Active = True
    else:
        # the date which you loan the book
        loanDate = dt.now()

        # the max date which you can return the book based on the loan type: 1=2days/ 2=5days/ 3=7days
        if book.loanType == 1:
            returnDate = loanDate + td(days=2)
        elif book.loanType == 2:
            returnDate = loanDate + td(days=5)
        elif book.loanType == 3:
            returnDate = loanDate + td(days=7)
        else:
            return jsonify({"msg": "error, incorrect loantype input"})
        loan = Loans(UserID=user.id, BookID=book_id, Active=True,loanDate=loanDate.strftime('%Y-%m-%d'), returnDate=returnDate.strftime('%Y-%m-%d'))
        db.session.add(loan)

    book.Active = False
    db.session.commit()
    return jsonify({"msg": "Book loaned"}), 200



@api.route('/updateBook/<int:book_id>', methods=['POST'])
@jwt_required()
def update_book(book_id):
    logged_user= get_jwt_identity()
    admin_emails = Users.query.filter_by(Role='Admin').first()
    if logged_user == admin_emails.Email:
        book = db.session.execute(db.select(Books).filter_by(id=book_id)).scalars().first()
        if book:
            data = request.get_json()
            new_bookName = data['bookName']
            new_bookAuthor = data['bookAuthor']
            new_bookPublished = data['bookPublished']
            
            book.bookName = new_bookName
            book.bookAuthor = new_bookAuthor
            book.bookPublished = new_bookPublished
            db.session.commit()
            return jsonify({"msg": "Book updated successfully"}), 200
            
        else:
            return jsonify({"msg": "Unauthorized"}), 403
        
@api.route('/returnBook/<int:book_id>', methods=['POST'])
@jwt_required()
def return_book(book_id):
    logged_user = get_jwt_identity()
    user = Users.query.filter_by(Email=logged_user).first()

    if not user:
        return jsonify({"msg": "User not found"}), 404

    print(f"Attempting to return BookID: {book_id} for UserID: {user.id}")

    loan = Loans.query.filter_by(BookID=book_id, UserID=user.id, Active=True).first()
    if not loan:
        print("Loaned book not found or already returned")
        return jsonify({"msg": "Loaned book not found or already returned"}), 404

    book = Books.query.filter_by(id=book_id).first()
    if not book:
        print("Book not found")
        return jsonify({"msg": "Book not found"}), 404

    print(f"Book ID: {book.id}, Loan ID: {loan.id}")

    try:
        book.Active = True
        loan.Active = False
        db.session.commit()
        print("Book returned successfully")
        return jsonify({"msg": "Book returned"}), 200
    except Exception as e:
        db.session.rollback()
        print(f"An error occurred while returning the book: {str(e)}")
        return jsonify({"msg": "An error occurred while returning the book", "error": str(e)}), 500



@api.route('/deleteUser/<int:user_id>', methods=['POST'])
@jwt_required()
def del_user(user_id):
    logged_user= get_jwt_identity()
    admin_emails = Users.query.filter_by(Role='Admin').first()
    if logged_user == admin_emails.Email:
        user = db.session.execute(db.select(Users).filter_by(id=user_id)).scalars().first()
        if user:
            print(user_id)
            user.Active = 0
            db.session.commit()
    return "user set to inactive"

@api.route('/updateUser/<int:user_id>', methods=['POST'])
@jwt_required()
def upd_user(user_id):
    logged_user = get_jwt_identity()
    user = Users.query.filter_by(Email=logged_user).first()

    if user and user.id == user_id:
        data = request.get_json()
        new_email = data.get("Email")
        new_password = data.get("Password")

        if new_email:
            user.Email = new_email
        if new_password:
            pwd_hash = generate_password_hash(new_password)
            user.Password = pwd_hash

        db.session.commit()
        return jsonify({"msg": "User info has been updated"}), 200
    else:
        return jsonify({"msg": "Unauthorized or user not found"}), 403

@api.route('/showUserLoans', methods=['GET'])
@jwt_required()
def show_user_loans():
    logged_user = get_jwt_identity()
    user = Users.query.filter_by(Email=logged_user).first()

    if not user:
        return jsonify({"msg": "User not found"}), 404
    
    loans = Loans.query.filter_by(UserID=user.id, Active=True).all()
    loaned_books = []

    for loan in loans:
        book = Books.query.filter_by(id=loan.BookID).first()
        loan_data = {
            'LoanID': loan.id,
            'BookID': loan.BookID,
            'Title': book.bookName,
            'LoanDate': loan.loanDate,
            'ReturnDate': loan.returnDate,
            'ImagePath': book.book_image_path
        }
        loaned_books.append(loan_data)
    
    response = {
        "Email": user.Email,
        "Loans": loaned_books
    }

    return jsonify(response), 200




if __name__ == '__main__':
    with api.app_context():
        db.create_all()
    api.run(debug=True,  port=5000)