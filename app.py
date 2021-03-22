# User login and authentication program in python flask

from flask import Flask, render_template, url_for, request, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, LoginManager, current_user, login_required, logout_user

# Creates an instance of the flask class
app = Flask(__name__)

# Configures the location of the database file
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.secret_key = "secret_key"

# Creates an instance of the sqlalchemy class
db = SQLAlchemy(app)

# Creates an instance of, and initializes the LoginManager class
login_manager = LoginManager()
login_manager.login_view = '/login'
login_manager.init_app(app)

# Creates the sqlalchemy database, to store the user information 
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(100), nullable = False)
    email = db.Column(db.String(200), nullable = False)
    password = db.Column(db.String(200), nullable = False)

# Flask uses this function upon ever database request, in order to ensure the request is from a valid user
@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

# Function for the main page of the website
@app.route('/')
def index():
    return render_template('index.html')

# Shows the profile of the user, if a user is logged in
@app.route('/profile')
@login_required
def profile():
    # The profile page outputs an h1 tag that contains the text "This is your profile, [username of the current user]"
    # The "user" argument passed in the function is what tells the html file the current user's name
    return render_template('profile.html', user=current_user.username)

# Function that renders the login page
@app.route('/login')
def login():
    return render_template('login.html')

# Function that logs the user in, after they hit the "login" button
@app.route('/login', methods=['POST'])
def login_post():
    # Gets the data inputed into login form and stores it in variables
    username = request.form.get('username')
    password = request.form.get('password')

    # Searches the database to see if there is a match for the username that was inputted 
    # It only checks the first result, because the inputted username should be exact
    user = User.query.filter_by(username=username).first()

    # If the user does not exist in the database, or the password is incorrect, it sends the user back to the login page with an error telling them to check their login details
    if not user or not check_password_hash(user.password, password):
        flash('Error: check your login details and try again.')
        return redirect(url_for('login'))
    
    # If the user hasnt been redirected back to the login page, it logs the user in and redirects them to their profile
    login_user(user)
    return redirect(url_for('profile'))

# Renders the signup page
@app.route('/signup')
def signup():
    return render_template('signup.html')

# Signs the user up for an account after they submit the sign up form on the sign up page
@app.route('/signup', methods=['POST'])
def signup_post():

    # Gets the data inputed into signup form and stores it in variables
    email = request.form.get('email')
    username = request.form.get('username')
    password = request.form.get('password')
    passwordrp = request.form.get('repeat-password')

    # Checks if the username already exists in the database 
    existing_user = User.query.filter_by(email=email).first()
    if existing_user: 
        flash('Error: email already exists.')
        return redirect(url_for('signup'))
    
    # The user needs to input their password twice, to make sure they didnt miss type the first time
    # This if statement checks if the two passwords match
    if password != passwordrp:
        flash('Error: passwords do not match.')
        return redirect(url_for('signup'))

    # If the user hasnt been redirected to the signup page, a new user is created and added to the database
    new_user = User(email=email, username=username, password=generate_password_hash(password, method='sha256'))

    try:
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    except: 
        flash('Error: could not add new user to database.')
        return redirect(url_for('signup'))

# If there is a user logged in, this function will log them out (once it is called)
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# Runs the app, if this file is not an import
if __name__ == "__main__":
    app.run(debug=True)