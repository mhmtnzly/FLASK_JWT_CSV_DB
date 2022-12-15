from flask import Flask, request, flash, jsonify, make_response, render_template, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from functools import wraps
import datetime
import uuid
from flask_migrate import Migrate
from models import db, User, Nasdaq
from dotenv import load_dotenv
import os
from extract import Extract
from werkzeug.utils import secure_filename
import pyodbc
from sendEmail import Email

load_dotenv()
DB_NAME = os.environ.get("DB_NAME")
DB_USER = os.environ.get("DB_USER")
DB_PASSWORD = os.environ.get("DB_PASSWORD")
DB_HOST = os.environ.get('DB_HOST')
ODBC = os.environ.get('ODBC')
connection_string = os.environ.get('connection_string')

app = Flask(__name__)
extract = Extract()
email = Email(connection_string)

UPLOAD_FOLDER = './uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SECRET_KEY'] = 'thisissecret'
app.config['SQLALCHEMY_DATABASE_URI'] = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}"

ALLOWED_EXTENSIONS = set(['csv', 'json'])


def allowed_file(fileName):
    return '.' in fileName and fileName.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS


def token_encode(public_id):
    token = jwt.encode({'public_id': public_id, 'exp': datetime.datetime.utcnow(
    ) + datetime.timedelta(minutes=300)}, app.config['SECRET_KEY'], 'HS256')
    session['token'] = token
    return token


db.init_app(app)
migrate = Migrate(app, db)


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        elif 'token' in session:
            token = session.get('token')
        if not token:
            return redirect(url_for('login'))
        try:
            data = jwt.decode(
                token, app.config['SECRET_KEY'], algorithms=["HS256"])
            currentUser = User.query.filter_by(
                public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'Token is invalid!'}), 401
        return f(currentUser, *args, **kwargs)
    return decorated


@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    elif request.method == 'POST' and request.form:
        form = request.form
        if 'username' not in form or 'password' not in form or 'email' not in form:
            return render_template('register.html')
        user_ = User.query.filter_by(name=form['username']).first()
        email_ = User.query.filter_by(email=form['email']).first()
        if user_ or email_:
            return render_template('register.html', flash='1')
        hashed_password = generate_password_hash(
            form['password'], method='sha256')
        public_id = str(uuid.uuid4())
        newUser = User(public_id=public_id,
                       name=form['username'], password=hashed_password, email=form['email'], admin=False)
        db.session.add(newUser)
        db.session.commit()
        token = token_encode(public_id)
        email.confirmationMail(
            to=form['email'], body=f'http://127.0.0.1:5000/confirm?token={token}', userName=form['username'])
        print(f'http://127.0.0.1:5000/confirm?token={token}')
        return redirect(url_for('login'))
    else:
        data = request.get_json()
        if 'name' not in data or 'password' not in data or 'email' not in data:
            return jsonify({'message': 'Missing data!'})
        # if this returns a user, then the email already exists in database
        user_ = User.query.filter_by(name=data['name']).first()
        email_ = User.query.filter_by(email=data['email']).first()
        if user_ or email_:  # if a user is found, we want to redirect back to signup page so user can try again
            return jsonify({'message': 'User exist!'})
        hashed_password = generate_password_hash(
            data['password'], method='sha256')
        newUser = User(public_id=str(uuid.uuid4()),
                       name=data['name'], password=hashed_password, email=data['email'], admin=False)
        db.session.add(newUser)
        db.session.commit()
        token = token_encode(public_id)
        email.confirmationMail(
            to=data['email'], body=f'http://127.0.0.1:5000/confirm?token={token}', userName=data['name'])
        return jsonify({'message': 'New user created!'})


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST' and request.form:
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(name=username).first()
        if not user:
            error = 'Invalid Credentials. Please try again.'
        elif not user.confirmed:
            error = 'The account is not confirmed.'
        elif check_password_hash(user.password, password):
            token = jwt.encode({'public_id': user.public_id, 'exp': datetime.datetime.utcnow(
            ) + datetime.timedelta(minutes=300)}, app.config['SECRET_KEY'], 'HS256')
            session['token'] = token
            return redirect(url_for('home', token=token))
        elif not check_password_hash(user.password, password):
            error = 'Wrong password. Please try again.'

    elif request.authorization:
        auth = request.authorization
        if not auth or not auth.username or not auth.password:
            return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})
        user = User.query.filter_by(name=auth.username).first()
        if not user:
            return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})
        if check_password_hash(user.password, auth.password):
            token = jwt.encode({'public_id': user.public_id, 'exp': datetime.datetime.utcnow(
            ) + datetime.timedelta(minutes=300)}, app.config['SECRET_KEY'], 'HS256')
            return jsonify({'token': token})
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})
    return render_template('login.html', error=error)


@ app.route('/')
@ app.route('/home')
@ token_required
def home(currentUser):
    return render_template('home.html', currentUser=currentUser)


@ app.route('/logout')
@ token_required
def logout(currentUser):
    session.clear()
    return render_template('index.html', currentUser=currentUser)


@ app.route('/user', methods=['GET'])
@ token_required
def get_all_users(currentUser):

    if not currentUser.admin:
        return jsonify({'message': 'Cannot perform that function!'})

    users = User.query.all()

    output = []

    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        output.append(user_data)

    return jsonify({'users': output})


@ app.route('/user/<public_id>', methods=['GET'])
@ token_required
def get_one_user(currentUser, public_id):

    if not currentUser.admin:
        return jsonify({'message': 'Cannot perform that function!'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found!'})

    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['password'] = user.password
    user_data['admin'] = user.admin

    return jsonify({'user': user_data})


@ app.route('/user/<public_id>', methods=['PUT'])
@ token_required
def promote_user(currentUser, public_id):
    if not currentUser.admin:
        return jsonify({'message': 'Cannot perform that function!'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found!'})

    user.admin = True
    db.session.commit()

    return jsonify({'message': 'The user has been promoted!'})


@ app.route('/user/<public_id>', methods=['DELETE'])
@ token_required
def delete_user(currentUser, public_id):
    if not currentUser.admin:
        return jsonify({'message': 'Cannot perform that function!'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found!'})

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message': 'The user has been deleted!'})


@ app.route('/nasdaq/<name>', methods=['GET'])
@ token_required
def get_nasdaq(currentUser, name):
    data_all = Nasdaq.query.filter(
        Nasdaq.name == name).order_by(Nasdaq.date).all()
    result = extract.get_nasdaq_data(data_all)
    return jsonify(result=result)


@ app.route('/create', methods=['GET', 'POST'])
@ token_required
def create(currentUser):
    result = []
    if request.method == 'POST':
        saveFiles = []
        files = request.files.getlist('file[]')

        for file in files:
            if allowed_file(file.filename):
                saveFiles.append(file)
                result.append({'filename': file.filename,
                               'success': True})
            else:
                result.append({'filename': file.filename,
                               'success': False, 'reason': 'File type is not supported!'})
        if len(saveFiles) > 0:
            for file in saveFiles:
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        uploadedFiles = extract.check_files()

        for file in uploadedFiles:
            df = extract.file_type(file)
            print(df)
            df = extract.df_arrange(df, file)
            df['user_id'] = currentUser.id
            df.to_sql(con=db.engine, name='nasdaq',
                      index=False, if_exists='append')
            extract.delete_file(file)
        email.emailSendForFile(to=currentUser.email,
                               body=result, userName=currentUser.name)
        # return result
    return render_template('drop.html', result=result, currentUser=currentUser)


@ app.route('/confirm', methods=['GET'])
@ token_required
def confirm(currentUser):
    print(currentUser)
    user = User.query.filter(User.email == currentUser.email).first()
    print(user.confirmed)
    if user.confirmed:
        message = 'Account already confirmed.'
    else:
        user.confirmed = True
        user.confirmed_on = datetime.datetime.now()
        db.session.commit()
        message = 'You have confirmed your account. Thanks!'
    return render_template('home.html', currentUser=currentUser, message=message)


@ app.route('/download', methods=['GET', 'POST'])
@ token_required
def download(currentUser, name=''):
    nameColumns = Nasdaq.query.with_entities(db.distinct(Nasdaq.name)).all()
    nameColumns = [col[0] for col in nameColumns]
    fileTypes = ALLOWED_EXTENSIONS
    if request.method == 'GET':
        return render_template('download.html', currentUser=currentUser, nameColumns=nameColumns, fileTypes=fileTypes)
    elif request.method == 'POST':
        nameColumn = request.form.get('name-columns')
        fileType = request.form.get("file-columns")
        data_all = Nasdaq.query.filter(
            Nasdaq.name == nameColumn).order_by(Nasdaq.date).all()
        if nameColumn:
            if fileType == 'csv':
                result = extract.download_csv_nasdaq(data_all)
                response = extract.file_download(nameColumn, result, fileType)
            elif fileType == 'json':
                result = extract.download_json_nasdaq(data_all)
                response = extract.file_download(nameColumn, result, fileType)
            return response
        else:
            message = 'You did not choose any data!'
    return render_template('download.html', nameColumns=nameColumns, fileTypes=fileTypes, message=message, currentUser=currentUser)


@app.route('/nasdaq/<name>/download/', methods=['GET'])
@token_required
def download_nasdaq(currentUser, name):
    data_all = Nasdaq.query.filter(
        Nasdaq.name == name).order_by(Nasdaq.date).all()
    result = extract.download_csv_nasdaq(data_all, name)
    return jsonify(result=result)


if __name__ == '__main__':
    app.run(debug=True)
