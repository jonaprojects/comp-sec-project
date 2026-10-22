from datetime import datetime, timezone
from functools import wraps

from flask import (
    Blueprint,
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.exceptions import BadRequestKeyError

from config import Config

from . import db
from .models import Client, User
from .utils.email_service import mask_email, send_reset_code
from .utils.reset_password_service import generate_reset_code
from .validators import (
    is_valid_email,
    is_valid_password,
    is_valid_phone,
    is_valid_username,
)

main = Blueprint("main", __name__)
METHOD_NOT_ALLOWED = 405
RESET_VERIFY_SECONDS = 300


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
        return abort(METHOD_NOT_ALLOWED)  # Invalid method type - manually handling it


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
        return abort(METHOD_NOT_ALLOWED)


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
@main.route("/profile")
def profile():
    return render_template("profile.html", user=g.user)


@main.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    errors = {}
    if request.method == "GET":
        return render_template("change_password.html", user=g.user, errors=errors)
    elif request.method == "POST":
        current_password = request.form.get("current_password")
        new_password = request.form.get("new_password")

        # sanity checks
        if not current_password or not new_password:
            errors["message"] = "Invalid Request. Try Again."
            return render_template("change_password.html", user=g.user, errors=errors)

        # validate that the password is correct
        if not g.user.check_password(current_password):
            errors["message"] = "Incorrect Data. Try Again."
            return render_template("change_password.html", user=g.user, errors=errors)

        # Check whether the new password follows our rules
        if not is_valid_password(new_password):
            errors["message"] = "Your password is too weak."
            return render_template("change_password.html", user=g.user, errors=errors)

        if g.user.check_password(new_password):
            # If new password = old password
            errors["message"] = "You cannot re-use the same password."
            return render_template("change_password.html", user=g.user, errors=errors)

        # update the password
        g.user.set_password(new_password)
        db.session.commit()
        flash("Password changed successfully!", "success")
        return redirect(url_for("main.change_password"))

    else:
        abort(METHOD_NOT_ALLOWED)


@main.route("/clients", methods=["GET"])
@login_required
def clients():
    query = db.select(Client)
    clients = db.session.scalars(query).all()
    return render_template("clients.html", user=g.user, clients=clients)


@main.route("/add-client", methods=["GET", "POST"])
@login_required
def add_client():
    errors = {}
    if request.method == "GET":
        return render_template("add_client.html", user=g.user, errors=errors)
    elif request.method == "POST":
        name = request.form.get("name")
        email = request.form.get("email")
        phone = request.form.get("phone")
        country = request.form.get("country")

        if not name or not email:
            errors["message"] = "Invalid Request."
            return render_template("add_client.html", user=g.user, errors=errors)

        if not is_valid_email(email):
            errors["email"] = "Invalid Email."
            return render_template("add_client.html", user=g.user, errors=errors)

        if phone and not is_valid_phone(phone):
            errors["phone"] = "Invalid Phone Number"
            return render_template("add_client.html", user=g.user, errors=errors)

        new_client = Client(name=name, email=email, phone=phone, country=country)
        db.session.add(new_client)
        db.session.commit()
        flash("Client Added successfully", "success")
        return redirect(url_for("main.clients"))
    else:
        abort(METHOD_NOT_ALLOWED)


@main.route("/forgot-password", methods=["GET", "POST"])
@login_required
def forgot_password():
    masked_email = mask_email(g.user.email)
    if request.method == "GET":
        return render_template(
            "forgot_password.html", user=g.user, masked_email=masked_email
        )
    elif request.method == "POST":
        # Invalidate previous reset authorization
        session.pop("reset_verified_user_id", None)
        session.pop("reset_verified_at", None)

        # generate reset code
        reset_code = generate_reset_code()

        # send to client email
        send_reset_code(g.user.email, reset_code)

        # hash, salt, and save in the db
        g.user.set_reset_code(reset_code)
        db.session.add(g.user)
        db.session.commit()
        flash('A Reset code was sent to your E-mail.', 'success')
        return redirect(url_for("main.verify_reset_code"))
    else:
        abort(METHOD_NOT_ALLOWED)


@main.route("/verify-reset-code", methods=["GET", "POST"])
@login_required
def verify_reset_code():
    errors = {}

    if request.method == "GET":
        return render_template("verify-reset-code.html", user=g.user, errors=errors)

    elif request.method == "POST":
        reset_code = request.form.get("reset-code")

        if not reset_code:
            errors["message"] = "Invalid Reset Code. Try Again."
            return render_template("verify-reset-code.html", user=g.user, errors=errors)

        is_valid_code = g.user.check_reset_code(reset_code)

        if not is_valid_code:
            errors["message"] = "Incorrect Reset Code. Try Again."
            return render_template("verify-reset-code.html", user=g.user, errors=errors)

        # mark that the code was verified
        session["reset_verified_user_id"] = g.user.id
        session["reset_verified_at"] = datetime.now(timezone.utc).timestamp()

        # clear the reset code data for next time
        g.user.clear_reset_code()
        db.session.commit()
        flash('Reset Code verified successfully!', 'success')
        return redirect(url_for("main.reset_password"))

    else:
        abort(METHOD_NOT_ALLOWED)


@main.route("/reset-password", methods=["GET", "POST"])
@login_required
def reset_password():
    """Reset password after accepting a reset code"""
    errors = {}

    # Don't let people who didn't complete the reset code to enter the page
    verified_id = session.get("reset_verified_user_id")
    verified_at = session.get("reset_verified_at")

    now = datetime.now(timezone.utc).timestamp()

    verified_on_time = (
        verified_id == g.user.id
        and isinstance(verified_at, (int, float))
        and verified_at <= now
        and now - verified_at <= RESET_VERIFY_SECONDS
    )

    if not verified_on_time:
        flash("Password Reset Failed.", "failure")
        return redirect(url_for("main.home"))

    if request.method == "GET":
        return render_template("reset-password.html", errors=errors)
    elif request.method == "POST":
        # Validate the new passwrord
        new_password = request.form.get("new_password")
        if not new_password or not is_valid_password(new_password):
            errors["password"] = "Password is too weak."
            return render_template("reset-password.html", errors=errors)

        # Reset the password
        g.user.set_password(new_password)
        db.session.commit()

        # clear session
        session.pop("reset_verified_user_id", None)
        session.pop("reset_verified_at", None)

        # signal success
        flash("Password reset successful", "success")
        return redirect(url_for("main.home"))

    else:
        abort(METHOD_NOT_ALLOWED)
