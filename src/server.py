import os
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_restful import Api, Resource
from dotenv import load_dotenv
from sqlalchemy import JSON

# Load environment variables
load_dotenv()

# Initialize Flask app and extensions
app = Flask(__name__)
api = Api(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv("JWT_SECRET_KEY", "your_secret_key")

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=False, nullable=False)
    email= db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)


class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(255))
    price = db.Column(db.Float)
    rating = db.Column(JSON, default=[])
    image_uri = db.Column(db.String)


class ContactForm(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    message = db.Column(db.Text, nullable=False)

# Routes and resources
class Register(Resource):
    def post(self):
        try:
            data = request.get_json()
            if not data:
                return {"message": "Missing JSON body"}, 400
            
            # Validate required fields
            if not data.get('name') or not data.get('email') or not data.get('password'):
                return {"message": "Name, email, and password are required"}, 400
            
            # Check if email is already registered
            existing_user = User.query.filter_by(email=data['email']).first()
            if existing_user:
                return {"message": "Email already registered"}, 409
            
            # Hash the password
            hashed_pw = bcrypt.generate_password_hash(data['password']).decode('utf-8')
            
            # Create new user
            user = User(email=data['email'], password=hashed_pw,name=data.get("name"))
            db.session.add(user)
            db.session.commit()
            
            return {"message": "User registered successfully"}, 201

        except KeyError as e:
            return {"message": f"Missing key: {str(e)}"}, 400
        
        except Exception as e:
            db.session.rollback()
            return {"message": f"An error occurred: {str(e)}"}, 500


class Login(Resource):
    def post(self):
        try:
            data = request.get_json()
            if not data:
                return {"message": "Missing JSON body"}, 400
            
            # Validate input fields
            if not data.get('email') or not data.get('password'):
                return {"message": "Username and password are required"}, 400
            
            user = User.query.filter_by(email=data['email']).first()
            
            # Check if user exists and password is correct
            if user is None:
                return {"message": "User not found"}, 404
            
            if not bcrypt.check_password_hash(user.password, data['password']):
                return {"message": "Incorrect password"}, 401
            
            # Create access token
            access_token = create_access_token(identity=user.id)
            return {"token": access_token}, 200

        except KeyError as e:
            return {"message": f"Missing key: {str(e)}"}, 400

        except Exception as e:
            return {"message": f"An error occurred: {str(e)}"}, 500


class ContactFormResource(Resource):
    def post(self):
        data = request.get_json()
      
        if not (data.get('name') and  data.get('email') and  data.get('message')):
            return {"message": "Name, email, and message are required"}, 400
        
        form = ContactForm(**data)
        db.session.add(form)
        db.session.commit()
        return {"message": "Form submitted successfully"}, 201

    @jwt_required()
    def get(self):
        forms = ContactForm.query.all()
        return [{"name": f.name, "email": f.email, "message": f.message} for f in forms], 200

class ProductResource(Resource):
    @jwt_required()
    def post(self):
        data = request.get_json()
        if not data.get('name') or not data.get('price'):
            return {"message": "Product name and price are required"}, 400
        
        product = Product(**data)
        db.session.add(product)
        db.session.commit()
        return {"message": "Product added"}, 201

    def get(self):
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        products = Product.query.paginate(page=page, per_page=per_page, error_out=False)
        
        return [{
            "id": p.id,
            "name": p.name,
            "category": p.category,
            "price": p.price,
            "image_uri":p.image_uri,
        } for p in products.items], 200

# API routes
api.add_resource(Register, '/register')
api.add_resource(Login, '/login')
api.add_resource(ContactFormResource, '/contact')
api.add_resource(ProductResource, '/products')


from faker import Faker
import random

fake = Faker()

def seed_products():
    categories = ['Electronics', 'Clothing', 'Books', 'Home & Kitchen', 'Toys', 'Sports', 'Beauty', 'Groceries']
    
    sample_products = []

    for _ in range(30):
        product = Product(
            name=fake.word().capitalize() + " " + fake.word().capitalize(),
            category=random.choice(categories),
            price=round(random.uniform(10, 500), 2),
            rating=[{"rating": round(random.uniform(1, 5), 1), "description": fake.sentence()} for _ in range(random.randint(1, 5))],
            image_uri=fake.image_url()
        )
        sample_products.append(product)

    db.session.bulk_save_objects(sample_products)
    db.session.commit()
    print("Database seeded with 30 products!")
    



    

# Run app
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # seed_products()
    app.run(host='0.0.0.0', port=5000,debug=True)
