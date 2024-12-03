# from flask import Flask, render_template

# app = Flask(__name__)

# @app.route('/')
# def index():
#     return render_template('index.html')



# if __name__ == "__main__":
#     app.run(debug=True)

from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import InputRequired, Length, Email
from config import Config
from models import db, User
import logger 
import pandas as pd
import logging

# Initialize app and configurations
app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"

# Load the Insurance dataset
dataset_path = 'Insurance Company dataset.xlsx'  # Adjust the path
insurance_data = pd.read_excel(dataset_path)

# Logging for monitoring and debugging
logging.basicConfig(filename='app.log', level=logging.WARNING)

# Enforce HTTPS in production
@app.before_request
def enforce_https_in_production():
    if not app.debug and request.headers.get('X-Forwarded-Proto') == 'http':
        return redirect(request.url.replace("http://", "https://"))

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Form for secure login and registration
class RegistrationForm(FlaskForm):
    username = StringField("Username", validators=[InputRequired(), Length(min=4, max=15)])
    email = StringField("Email", validators=[InputRequired(), Email()])
    password = PasswordField("Password", validators=[InputRequired(), Length(min=8)])

class LoginForm(FlaskForm):
    username = StringField("Username", validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField("Password", validators=[InputRequired(), Length(min=8)])

# Registration Route
@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user is None:
            new_user = User(username=form.username.data, email=form.email.data, role="Finance")  # Default role for demo
            new_user.set_password(form.password.data)
            db.session.add(new_user)
            db.session.commit()
            flash("Registration successful!", "success")
            return redirect(url_for("login"))
        flash("Username already exists.", "danger")
    return render_template("register.html", form=form)

# Login Route
@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            logger.info(f"User logged in: {user.username}")
            return redirect(url_for("dashboard"))
        flash("Invalid username or password.", "danger")
        logger.warning(f"Failed login attempt: {form.username.data}")
    return render_template("login.html", form=form)

# Dashboard Route
@app.route("/dashboard")
@login_required
def dashboard():
    if current_user.role == "Finance":
        return redirect(url_for("finance_dashboard"))
    elif current_user.role == "Executive":
        return redirect(url_for("executive_dashboard"))
    else:
        logging.warning(f"Unauthorized role access attempt by user: {current_user.username}")
        return render_template("error.html", message="403 Forbidden"), 403

# Finance Dashboard
@app.route("/finance-dashboard")
@login_required
def finance_dashboard():
    if current_user.role != "Finance":
        logging.warning(f"Unauthorized access attempt to finance dashboard by user: {current_user.username}")
        return render_template("error.html", message="403 Forbidden"), 403
    return render_template("finance_dashboard.html", data=insurance_data.to_html())

# Executive Dashboard
@app.route("/executive-dashboard")
@login_required
def executive_dashboard():
    if current_user.role != "Executive":
        logging.warning(f"Unauthorized access attempt to executive dashboard by user: {current_user.username}")
        return render_template("error.html", message="403 Forbidden"), 403
    return render_template("executive_dashboard.html", data=insurance_data.head().to_html())

# Logout Route
@app.route("/logout")
@login_required
def logout():
    logging.info(f"User logged out: {current_user.username}")
    logout_user()
    return redirect(url_for("login"))

# Error Handling
@app.errorhandler(403)
def access_forbidden(error):
    logging.warning(f"403 Forbidden: {error}")
    return render_template("error.html", message="403 Forbidden"), 403

@app.errorhandler(404)
def not_found(error):
    logging.warning(f"404 Not Found: {error}")
    return render_template("error.html", message="404 Not Found"), 404

@app.errorhandler(500)
def internal_error(error):
    logging.critical(f"500 Internal Server Error: {error}")
    return render_template("error.html", message="500 Internal Server Error"), 500

if __name__ == "__main__":
    app.run()
