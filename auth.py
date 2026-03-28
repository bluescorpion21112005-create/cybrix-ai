"""
auth.py — Authentication blueprint (register / login / logout).
"""
import logging
import re

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import login_required, login_user, logout_user
from werkzeug.security import check_password_hash, generate_password_hash

from models import User, db

logger = logging.getLogger(__name__)
auth_bp = Blueprint("auth", __name__)

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _validate_registration(full_name: str, email: str, password: str, confirm: str) -> str | None:
    """Returns an error message string, or None if valid."""
    if not full_name or not email or not password or not confirm:
        return "All fields are required."
    if not _EMAIL_RE.match(email):
        return "Invalid email address."
    if len(password) < 8:
        return "Password must be at least 8 characters."
    if password != confirm:
        return "Passwords do not match."
    return None


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        error = _validate_registration(full_name, email, password, confirm)
        if error:
            flash(error, "danger")
            return render_template("register.html")

        if User.query.filter_by(email=email).first():
            flash("Email already registered.", "warning")
            return redirect(url_for("auth.login"))

        user = User(
            full_name=full_name,
            email=email,
            password_hash=generate_password_hash(password),
            auth_provider="local",
        )
        db.session.add(user)
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
            logger.exception("DB error during registration for %s", email)
            flash("Registration failed. Please try again.", "danger")
            return render_template("register.html")

        login_user(user)
        logger.info("New user registered: %s", email)
        flash("Account created successfully.", "success")
        return redirect(url_for("home"))

    return render_template("register.html")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not email or not password:
            flash("Email and password are required.", "danger")
            return render_template("login.html")

        user = User.query.filter_by(email=email).first()

        if not user or not user.password_hash:
            flash("Invalid credentials.", "danger")
            return render_template("login.html")

        if not check_password_hash(user.password_hash, password):
            logger.warning("Failed login attempt for %s", email)
            flash("Invalid credentials.", "danger")
            return render_template("login.html")

        login_user(user)
        logger.info("User logged in: %s", email)
        # Login bo'lgandan keyin to'g'ridan-to'g'ri index (home) sahifasiga o'tish
        next_page = request.args.get("next")
        return redirect(next_page if next_page else url_for("home"))

    return render_template("login.html")


@auth_bp.route("/logout")
@login_required
def logout():
    logger.info("User logged out: %s", getattr(request, "_current_user_email", "unknown"))
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))
