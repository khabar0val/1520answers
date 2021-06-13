from flask import Flask, render_template, request, redirect, flash, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///answers.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'khabalexden'
app.config['SESSION_TYPE'] = 'filesystem'
db = SQLAlchemy(app)
login_manager = LoginManager(app)

# Creating a table named Article
class Article(db.Model):
    __tablename__ = 'articles'

    phio = db.Column(db.Text, primary_key=True)
    classes = db.Column(db.Text, primary_key=True)
    answers = db.Column(db.Text, primary_key=True)

    def __init__(self, phio, classes, answers):
        self.phio = phio
        self.classes = classes
        self.answers = answers

    def __repr__(self):
        return '<Article %r>' % self.phio

# Creating a table named User
class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer(), primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(100), nullable=False)

    def __repr__(self):
        return "<{}:{}>".format(self.id, self.username)

# Initialization in flask_login
@login_manager.user_loader
def load_user(user_id):
    return db.session.query(User).get(user_id)

# Login
@app.route('/', methods=['GET', 'POST'])
def login_page():
    # Get info from form
    username = request.form.get('username')
    password = request.form.get('password')

    if username and password:
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)

            return redirect('/home')

        else:
            flash('Login or password is not correct')

    else:
        flash('Please fill login and password fields')

    return render_template('signin.html')

# Registration
@app.route('/signup', methods=['GET', 'POST'])
def register():
        # Get info from form
        username = request.form.get('username')
        password = request.form.get('password')

        if request.method == 'POST':
            if not (username or password):
                print('Please, fill all fields!')

            elif username and password:
                hash_pwd = generate_password_hash(password)
                new_user = User(username=username, password=hash_pwd)
                db.session.add(new_user)
                db.session.commit()

                return redirect('/')

        return render_template('signup.html')

# Main page(answers)
@app.route('/home', methods = ['POST', 'GET'])
def home():
    if request.method == 'POST':
        # Get answers from form
        phio = request.form['phio']
        classes = request.form['classes']
        answers = request.form['answers']

        # Put answers into answer's db
        article = Article(phio=phio, classes=classes, answers=answers)

        try:
            # Commit session
            db.session.add(article)
            db.session.commit()
            return redirect('/done')

        except:
            return "Ошибка"
    else:
        return render_template('index.html')

# Done page
@app.route('/done')
def done():
    return render_template('done.html')

# RUN
if __name__ == "__main__":

    app.debug = True
    app.run()