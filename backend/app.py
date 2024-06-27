from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import Integer, String, select
from sqlalchemy.orm import Mapped, mapped_column
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS

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
    id: Mapped[int] = mapped_column(primary_key=True)
    bookName: Mapped[str] = mapped_column(unique=True)
    bookAuthor: Mapped[str]
    bookPublished: Mapped[int]
    Active: Mapped[bool]

class Users(db.Model):
    id: Mapped[int] = mapped_column(primary_key=True)
    Email: Mapped[str] = mapped_column(unique=True)
    Password: Mapped[str]
    Active: Mapped[bool]

class Admin(db.Model):
    id: Mapped[int] = mapped_column(primary_key=True)
    Email: Mapped[str] = mapped_column(unique=True)
    Password: Mapped[str]
    Active: Mapped[bool]

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

    # return jsonify({"msg": "User registered successfully"}), 201

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
    password= data['Password']

    user = Users.query.filter_by(Email=Email).first() or Admin.query.filter_by(Email=Email).first()

    if not user or not check_password_hash(user.Password, password):
        return jsonify({
            'message': 'WRONG'
        }), 401
    
    acc_token = create_access_token(identity=Email)
    return jsonify({'acc_token': acc_token}), 200

@api.route('/addBook', methods=['POST'])
@jwt_required()
def add_book():
    logged_user = get_jwt_identity()
    if logged_user:
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

if __name__ == '__main__':
    with api.app_context():
        db.create_all()
    api.run(debug=True)