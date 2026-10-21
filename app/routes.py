from flask import (
    Blueprint,
    abort,
    flash,
    redirect,
    render_template,
    request,
    url_for,
    session,
    g,
)
from werkzeug.exceptions import BadRequestKeyError
from functools import wraps

from config import Config

from . import db
from .models import User
from .validators import is_valid_email, is_valid_password, is_valid_username

main = Blueprint("main", __name__)


@main.before_request
def load_logged_in_user():
    user_id = session.get("user_id")

    if user_id is None:
        g.user = None
    else:
        g.user = db.session.get(User, user_id)
        if g.user is None:
            session.clear()


@main.route("/", methods=["GET", "POST"])
def home():
    return render_template("home.html", user=g.user)


@main.route("/about")
def about():
    return "<h1>This page is under development</h1>"


@main.route("/contact")
def contact():
    return "<h1>This page is under development</h1>"


@main.route("/register", methods=["GET", "POST"])
def register():
    errors = {}
    config_dict = Config.get_validation_dict()
    if request.method == "GET":
        return render_template(
            "register.html", validation_rules=config_dict, errors={}, user=g.user
        )
    elif request.method == "POST":  # TODO: Update dummy handling
        try:
            username = request.form["username"]
            email = request.form["email"]
            password = request.form["password"]

            # 1. Validate the data according to the config
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
                return render_template(
                    "register.html",
                    validation_rules=config_dict,
                    errors=errors,
                    user=g.user,
                ), 400

            # 2. Check if the username already exist.
            query = db.select(User.id).where(User.username == username)
            existing_user_id = db.session.scalar(query)

            if existing_user_id is not None:
                # Then the user already exists!
                flash("User already exist!", "Change one or more fields.")
                errors["username"] = "This username is taken."
                return render_template(
                    "register.html",
                    validation_rules=config_dict,
                    errors=errors,
                    user=g.user,
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
                user=g.user,
            ), 400
    else:
        return abort(405)  # Invalid method type - manually handling it


@main.route("/login", methods=["GET", "POST"])
def login():
    errors = {}

    if request.method == "GET":
        return render_template("login.html", errors=errors, user=g.user)
    elif request.method == "POST":
        # 1. Validate user data
        username = request.form.get("username")
        password = request.form.get("password")

        # 1.1 sanity checks
        if username is None:
            errors["username"] = "Invalid Username. Try Again."
            return render_template("login.html", errors=errors, user=g.user)

        if password is None:
            errors["password"] = "Invalid Password. Try Again."
            return render_template("login.html", errors=errors, user=g.user)

        # 1.2. Verify that the user actually exists.
        query = db.select(User).where(User.username == username)
        user = db.session.scalar(query)

        if user is None:
            # Then the user doesn't exist - cannot log in.
            errors["username"] = "User does not exist."
            return render_template("login.html", errors=errors, user=g.user)
            # ? Potential risk: do we want to let attackers know which users exist or not?

        # 1.3 Verify that the password is correct (salt, hash and compare)
        if not user.check_password(password):
            errors["password"] = "Incorrect Password!"
            # TODO: Employ some retry mechanism or counter here, or cooldowns
            return render_template("login.html", errors=errors, user=g.user)

        # 1.4 - Request Authenticated - initiate new session
        session.clear()
        session["user_id"] = user.id
        return redirect(url_for("main.home"))
    else:
        return abort(405)


@main.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("main.login"))


def login_required(f):
    @wraps(f)  # to not lose the original function attributes
    def decorated(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("main.login"))

        return f(*args, **kwargs)

    return decorated

@login_required 
@main.route('/profile')
def profile():
    return render_template('profile.html', user=g.user)