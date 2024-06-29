from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import Integer, String, select
from sqlalchemy.orm import Mapped, mapped_column
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS, cross_origin

api = Flask(__name__)
CORS(api)
api.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///library.db"
api.config['SECRET_KEY'] = 'your_secret_key_here'
api.config['JWT_SECRET_KEY'] = 'jwt_secret_key_here'

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
    Active = db.Column(db.Boolean)

class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    Email = db.Column(db.String, unique=True)
    Password = db.Column(db.String)
    Active = db.Column(db.Boolean)

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    Email = db.Column(db.String, unique=True)
    Password = db.Column(db.String)
    Active = db.Column(db.Boolean)

class Loans(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    UserID = db.Column(db.Integer, db.ForeignKey('users.id'))
    BookID = db.Column(db.Integer, db.ForeignKey('books.id'))
    Active = db.Column(db.Boolean)

    user = db.relationship('Users', backref='loans')
    book = db.relationship('Books', backref='loans')

# ADD ADMIN ROUTE, ADMIN ADDED SO ROUTE IS LEFT OUT OF THE APP

# @api.route('/registerAdmin', methods=['POST'])
# def registerAdmin():
#     data = request.get_json()
#     if not data or not data.get('Email') or not data.get('Password'):
#         return jsonify({"msg": "Missing email or password"}), 400

#     Email = data['Email']
#     password= data['Password']

#     if Admin.query.filter_by(Email=Email).first() is not None:
#         return jsonify({"msg": "User already exists"}), 409

#     pwd_hash = generate_password_hash(password)
#     new_Admin = Admin(Email=Email, Password=pwd_hash, Active=True)
#     db.session.add(new_Admin)
#     db.session.commit()

#     return jsonify({"msg": "User registered successfully"}), 201

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
    new_user = Users(Email=Email, Password=pwd_hash, Active=True)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"msg": "User registered successfully"}), 201

@api.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    Email = data['Email']
    password = data['Password']

    user = Users.query.filter_by(Email=Email).first() or Admin.query.filter_by(Email=Email).first()
    
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

    acc_token = create_access_token(identity=Email)
    return jsonify({'acc_token': acc_token}), 200


@api.route('/addBook', methods=['POST'])
@jwt_required()
def add_book():
    logged_user = get_jwt_identity()
    admin_emails = [admin.Email for admin in db.session.execute(db.select(Admin)).scalars().all()]
    if logged_user in admin_emails:
        print(logged_user)
        data = request.get_json()
        bookName = data['bookName']
        bookAuthor = data['bookAuthor']
        bookPublished = data['bookPublished']
        if Books.query.filter_by(bookName=bookName).first() is not None:
            return jsonify({"msg": "Book name already exists"}), 409
        new_book = Books(bookName=bookName, bookAuthor=bookAuthor, bookPublished=bookPublished, Active=True)
        db.session.add(new_book)
        db.session.commit()
        return f'{bookName} successfully added'
    else:
        return jsonify({"msg":"User does not have authority for this action"})

@api.route('/showBook', methods=['GET'])
def show_books():
    book_list = Books.query.filter(Books.Active == True).all()
    books = [{"id": book.id, "bookName": book.bookName, "bookAuthor": book.bookAuthor, "bookPublished": book.bookPublished} for book in book_list]
    return jsonify(books)

@api.route('/showUser', methods=['GET'])
def show_users():
    user_list = db.session.execute(db.select(Users)).scalars().all()
    users = [{"Email": user.Email, "Password": user.Password} for user in user_list]
    return jsonify(users)

@api.route('/delBook/<int:book_id>', methods=['DELETE'])
@jwt_required()
def del_book(book_id):
    logged_user = get_jwt_identity()
    admin_emails = [admin.Email for admin in db.session.execute(db.select(Admin)).scalars().all()]
    if logged_user in admin_emails:
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

    # Fetch user based on logged-in email, assuming it's a regular user
    user = Users.query.filter_by(Email=logged_user).first()

    if not user:
        return jsonify({"msg": "User not found"}), 404

    book = Books.query.filter_by(id=book_id).first()
    
    if not book:
        return jsonify({"msg": "Book not found"}), 404
    
    if book.Active == 0:
        return jsonify({"msg": "book is currently loaned"})
        

    # Create loan data
    loan_data = Loans(UserID=user.id, BookID=book.id, Active=True)
    book.Active = 0
    db.session.add(loan_data)
    db.session.commit()

    return "Loan added successfully", 200

@api.route('/updateBook/<int:book_id>', methods=['POST'])
@jwt_required()
def update_book(book_id):
    logged_user= get_jwt_identity()
    admin_emails = [admin.Email for admin in db.session.execute(db.select(Admin)).scalars().all()]
    if logged_user in admin_emails:
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
    logged_user =  get_jwt_identity()
    user = Users.query.filter_by(Email=logged_user).first()

    if not user:
        return jsonify({"msg": "User not found"}), 404
    
    loaned_book = Loans.query.filter_by(id=book_id).first()
    if not loaned_book:
        return jsonify({"msg": "Loaned book not found"}), 404
    
    book = Books.query.filter_by(id=book_id).first()
    print(book.id, loaned_book.id)
    book.Active = 1
    loaned_book.Active = 0
    db.session.commit()
    return jsonify({"msg": "book returned"})


@api.route('/deleteUser/<int:user_id>', methods=['POST'])
@jwt_required()
def del_user(user_id):
    logged_user= get_jwt_identity()
    admin_emails = [admin.Email for admin in db.session.execute(db.select(Admin)).scalars().all()]
    if logged_user in admin_emails:
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



if __name__ == '__main__':
    with api.app_context():
        db.create_all()
    api.run(debug=True,  port=5000)