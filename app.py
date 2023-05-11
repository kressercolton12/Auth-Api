from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import exc
from flask_marshmallow import Marshmallow
from flask_cors import CORS
from flask_bcrypt import Bcrypt
import os

app = Flask(__name__)
CORS(app)

basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'app.sqlite')

db = SQLAlchemy(app)
ma = Marshmallow(app)
bc = Bcrypt(app)

class User(db.Model):
    id = db.Column (db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False, unique=True)
    password = db.Column(db.String, nullable=False)
    email = db.Column(db.String, unique=True)

    def __init__(self, unsername, password, email):
        self.username = unsername
        self.password = password
        self.email = email

class UserSchema(ma.Schema):
    class Meta:
        fields = ('id', 'username', 'password', 'email')

user_schema = UserSchema()
multi_user_schema = UserSchema(many=True)    

@app.route('/user/create', methods=["POST"])
def create_account():
    if request.content_type != 'application/json':
        return jsonify("Error: JSONIFY")
    
    post_data = request.get_json()
    username = post_data.get("username")
    email = post_data.get("email")
    password = post_data.get("password")

    pw_hash = bc.generate_password_hash(password, 15).decode("utf-8")

    new_user = User(username, pw_hash, email)
    db.session.add(new_user)
    db.session.commit()

    return jsonify("User Created!", user_schema.dump(new_user))

@app.route("/verify", methods=["POST"])
def verify():
    if request.content_type != "application/json":
        return jsonify("Check your format of sending Data")
    post_data = request.get_json()
    username = post_data.get("username")
    password = post_data.get("password")
    email = post_data.get("email")
        
    user = db.session.query(User).filter(
        User.username == username)

    if user is None:
        return jsonify("User information not verified")
    if not bc.check_password_hash(user.password, password):
        return jsonify("User information not verified")
    
    return jsonify("User Verified")


@app.route('/user/get')
def get_users():
    users = db.session.query(User).all()
    return jsonify(multi_user_schema.dump(users))

@app.route('/user/delete/<id>', methods=["DELETE"])
def delete_user(id):
    delete_user = db.session(User).filter(User.id == id).first()
    db.session.delete(delete_user)
    db.session.commit()
    return jsonify("User Profile has been DELETED!")


@app.route('/user/update/<id>', methods=['PUT'])
def update_user(id):
    if request.content_type != 'application/json':
        return jsonify("Send your stuff as JSON not other types!")
    put_data = request.get_json()
    username = put_data.get('username')
    email = put_data.get('email')
    edit_user = db.session.query(User).filter(User.id == id).first()

    if username != None:
        edit_user.username = username
    if email != None:
        edit_user.email = email

    db.session.commit()
    return jsonify("User Information Has Been Updated")


@app.route('/user/editpw/<id>', methods=["PUT"])
def edit_pw(id):
    if request.content_type != 'application/json':
        return jsonify("Error updating PW")
    password = request.get_json().get("password")
    user = db.session.query(User).filter(User.id == id).first()
    pw_hash = bc.generate_password_hash(password, 15).decode('utf-8')
    user.password = pw_hash

    db.session.commit()

    return jsonify("Password Changed Succesful", user_schema.dump(user))




if __name__ == "__main__":
    app.run(debug = True)