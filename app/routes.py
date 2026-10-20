from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from werkzeug.exceptions import BadRequestKeyError

from config import Config

from . import db
from .models import User
from .validators import is_valid_email, is_valid_password, is_valid_username

main = Blueprint("main", __name__)


@main.route("/", methods=["GET", "POST"])
def home():
    return render_template("home.html")


@main.route("/about")
def about():
    return "<h1>This page is under development</h1>"


@main.route("/contact")
def contact():
    return "<h1>This page is under development</h1>"


@main.route("/register", methods=["GET", "POST"])
def register():
    config_dict = Config.get_validation_dict()
    if request.method == "GET":
        return render_template("register.html", validation_rules=config_dict)
    elif request.method == "POST":  # TODO: Update dummy handling
        try:
            username = request.form["username"]
            email = request.form["email"]
            password = request.form["password"]

            # 1. Validate the data according to the config
            errors = {}
            is_valid = True

            if not is_valid_username(username):
                errors["username"] = "Invalid Username."
                is_valid = False

            if not is_valid_email(email):
                errors["email"] = "Invalid Email."
                is_valid = False

            if not is_valid_password(password):
                errors["password"] = "Invalid Password."
                is_valid = False
                # We can later on provide more useful message

            if not is_valid:
                flash("Registeration Failed.", "Bad Request.")
                return render_template(
                    "register.html",
                    validation_rules=config_dict,
                    errors=errors,
                ), 400

            # 2. Check if the username already exist.
            query = db.select(User).where(User.username == username)
            existing_user = db.session.scalar(query)

            if existing_user is not None:
                # Then the user already exists!
                flash("User already exist!")
                errors["username"] = "This username is taken."
                return render_template(
                    "register.html",
                    validation_rules=config_dict,
                    errors=errors,
                ), 400
            # 3. Create the user, and add it to the table
            new_user = User(username=username, email=email)

            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()

            # TODO: But here we need to add user data and a session
            return redirect(url_for("main.home"))

        except BadRequestKeyError:
            # Would be thrown if one or more properties don't exist.
            flash("Error!", "Invalid Request.")
            return render_template(
                    "register.html",
                    validation_rules=config_dict,
                    errors=errors,
                ), 400
    else:
        return abort(405)  # Invalid method type - manually handling it


@main.route("/login")
def login():
    return render_template("login.html")
