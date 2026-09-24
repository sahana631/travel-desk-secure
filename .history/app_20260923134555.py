import logging
import os
from datetime import date, datetime
from functools import wraps
from pathlib import Path

import bleach
from flask import Flask, flash, g, redirect, render_template, session, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_sqlalchemy import SQLAlchemy
from flask_talisman import Talisman
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFError, CSRFProtect
from sqlalchemy import Date, DateTime, ForeignKey, String, Text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash, generate_password_hash
from wtforms import PasswordField, SelectField, StringField, SubmitField, TextAreaField
from wtforms.fields import DateField
from wtforms.validators import DataRequired, Length, ValidationError


BASE_DIR = Path(__file__).resolve().parent
secret_key = os.environ.get("SECRET_KEY")
if not secret_key:
    raise RuntimeError("SECRET_KEY must be configured in the environment.")


class Base(DeclarativeBase):
    pass


db = SQLAlchemy(model_class=Base)
csrf = CSRFProtect()
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[],
    storage_uri=os.environ.get("RATELIMIT_STORAGE_URI", "memory://"),
)

app = Flask(__name__)
app.config.update(
    SECRET_KEY=secret_key,
    SQLALCHEMY_DATABASE_URI=os.environ.get(
        "DATABASE_URL", f"sqlite:///{BASE_DIR / 'travel_desk_secure.db'}"
    ),
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_PERMANENT=True,
)

db.init_app(app)
csrf.init_app(app)
limiter.init_app(app)
Talisman(
    app,
    force_https=False,
    frame_options="DENY",
    content_security_policy={
        "default-src": "'self'",
        "style-src": "'self'",
        "script-src": "'self'",
        "img-src": ["'self'", "data:"],
        "form-action": "'self'",
        "frame-ancestors": "'none'",
    },
)


class User(db.Model):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(80), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    trips: Mapped[list["Trip"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )


class Trip(db.Model):
    __tablename__ = "trips"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    destination: Mapped[str] = mapped_column(String(200), nullable=False)
    start_date: Mapped[date] = mapped_column(Date, nullable=False)
    end_date: Mapped[date] = mapped_column(Date, nullable=False)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    user: Mapped[User] = relationship(back_populates="trips")
    itinerary_items: Mapped[list["ItineraryItem"]] = relationship(
        back_populates="trip", cascade="all, delete-orphan", order_by="ItineraryItem.item_datetime"
    )


class ItineraryItem(db.Model):
    __tablename__ = "itinerary_items"

    id: Mapped[int] = mapped_column(primary_key=True)
    trip_id: Mapped[int] = mapped_column(ForeignKey("trips.id"), nullable=False)
    item_type: Mapped[str] = mapped_column(String(30), nullable=False)
    item_datetime: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    trip: Mapped[Trip] = relationship(back_populates="itinerary_items")


def sanitize_text(value: str | None) -> str:
    if not value:
        return ""
    return bleach.clean(value.strip(), tags=[], attributes={}, protocols=[], strip=True)


@app.template_filter("clean_text")
def clean_text_filter(value):
    return sanitize_text(value)


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(max=80)])
    password = PasswordField("Password", validators=[DataRequired(), Length(max=255)])
    submit = SubmitField("Log in")


class RegisterForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(max=80)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=8, max=255)])
    submit = SubmitField("Create account")

    def validate_username(self, field):
        username = sanitize_text(field.data)
        if not username:
            raise ValidationError("Username is required.")
        if db.session.scalar(db.select(User).where(User.username == username)):
            raise ValidationError("That username is already taken.")
        field.data = username


class TripForm(FlaskForm):
    destination = StringField(
        "Destination", validators=[DataRequired(), Length(max=200)]
    )
    start_date = DateField(
        "Start date", format="%Y-%m-%d", validators=[DataRequired()]
    )
    end_date = DateField("End date", format="%Y-%m-%d", validators=[DataRequired()])
    notes = TextAreaField("Notes", validators=[Length(max=5000)])
    submit = SubmitField("Book trip")

    def validate_destination(self, field):
        field.data = sanitize_text(field.data)
        if not field.data:
            raise ValidationError("Destination is required.")

    def validate_notes(self, field):
        field.data = sanitize_text(field.data)

    def validate_end_date(self, field):
        if self.start_date.data and field.data and field.data < self.start_date.data:
            raise ValidationError("End date must be on or after the start date.")


class ItineraryForm(FlaskForm):
    item_type = SelectField(
        "Type",
        choices=[
            ("Flight", "Flight"),
            ("Hotel", "Hotel"),
            ("Activity", "Activity"),
            ("Other", "Other"),
        ],
        validators=[DataRequired()],
    )
    item_datetime = StringField(
        "Date and time", validators=[DataRequired(), Length(max=16)]
    )
    description = TextAreaField("Description", validators=[Length(max=5000)])
    submit = SubmitField("Add to itinerary")

    def validate_item_datetime(self, field):
        try:
            datetime.fromisoformat(field.data)
        except (TypeError, ValueError):
            raise ValidationError("Enter a valid date and time.")

    def validate_description(self, field):
        field.data = sanitize_text(field.data)


class DeleteForm(FlaskForm):
    submit = SubmitField("Delete")


def login_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            flash("Please log in to continue.", "info")
            return redirect(url_for("login"))
        return view(**kwargs)

    return wrapped_view


def owned_trip_or_none(trip_id: int) -> Trip | None:
    if g.user is None:
        return None
    return db.session.scalar(
        db.select(Trip).where(Trip.id == trip_id, Trip.user_id == g.user.id)
    )


@app.before_request
def load_user():
    g.user = None
    user_id = session.get("user_id")
    if user_id is not None:
        g.user = db.session.get(User, user_id)
        if g.user is None:
            session.clear()


@app.context_processor
def inject_user():
    return {
        "current_user": getattr(g, "user", None),
        "logout_form": DeleteForm(prefix="logout"),
    }


@app.route("/")
def index():
    return redirect(url_for("dashboard" if g.user else "login"))


@app.route("/register", methods=("GET", "POST"))
def register():
    if g.user is not None:
        return redirect(url_for("dashboard"))

    form = RegisterForm()
    if form.validate_on_submit():
        user = User(
            username=form.username.data,
            password_hash=generate_password_hash(form.password.data),
        )
        db.session.add(user)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash("That username is already taken.", "error")
        else:
            flash("Your account is ready. Please log in.", "success")
            return redirect(url_for("login"))
    return render_template("auth/register.html", form=form)


@app.route("/login", methods=("GET", "POST"))
@limiter.limit("5 per minute")
def login():
    if g.user is not None:
        return redirect(url_for("dashboard"))

    form = LoginForm()
    if form.validate_on_submit():
        username = sanitize_text(form.username.data)
        user = db.session.scalar(db.select(User).where(User.username == username))
        if user is None or not check_password_hash(user.password_hash, form.password.data):
            flash("Incorrect username or password.", "error")
        else:
            session.clear()
            session.permanent = True
            session["user_id"] = user.id
            return redirect(url_for("dashboard"))
    return render_template("auth/login.html", form=form)


@app.post("/logout")
@login_required
def logout():
    form = DeleteForm(prefix="logout")
    if form.validate_on_submit():
        session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    trips = db.session.scalars(
        db.select(Trip)
        .where(Trip.user_id == g.user.id)
        .order_by(Trip.start_date.asc(), Trip.id.desc())
    ).all()
    delete_forms = {trip.id: DeleteForm(prefix=f"delete-{trip.id}") for trip in trips}
    return render_template("dashboard.html", trips=trips, delete_forms=delete_forms)


@app.route("/trips/new", methods=("GET", "POST"))
@login_required
def create_trip():
    form = TripForm()
    if form.validate_on_submit():
        trip = Trip(
            user_id=g.user.id,
            destination=sanitize_text(form.destination.data),
            start_date=form.start_date.data,
            end_date=form.end_date.data,
            notes=sanitize_text(form.notes.data),
        )
        db.session.add(trip)
        db.session.commit()
        flash("Trip booked.", "success")
        return redirect(url_for("dashboard"))
    return render_template("trip_form.html", form=form, form_title="Book a trip", trip=None)


@app.route("/trips/<int:trip_id>/edit", methods=("GET", "POST"))
@login_required
def edit_trip(trip_id):
    trip = owned_trip_or_none(trip_id)
    if trip is None:
        return render_template("error.html", message="The requested trip is not available."), 404

    form = TripForm(obj=trip)
    if form.validate_on_submit():
        trip.destination = sanitize_text(form.destination.data)
        trip.start_date = form.start_date.data
        trip.end_date = form.end_date.data
        trip.notes = sanitize_text(form.notes.data)
        db.session.commit()
        flash("Trip updated.", "success")
        return redirect(url_for("trip_detail", trip_id=trip.id))
    return render_template("trip_form.html", form=form, form_title="Edit trip", trip=trip)


@app.post("/trips/<int:trip_id>/delete")
@login_required
def delete_trip(trip_id):
    trip = owned_trip_or_none(trip_id)
    form = DeleteForm(prefix=f"delete-{trip_id}")
    if trip is None:
        return render_template("error.html", message="The requested trip is not available."), 404
    if form.validate_on_submit():
        db.session.delete(trip)
        db.session.commit()
        flash("Trip deleted.", "success")
    return redirect(url_for("dashboard"))


@app.route("/trips/<int:trip_id>")
@login_required
def trip_detail(trip_id):
    trip = owned_trip_or_none(trip_id)
    if trip is None:
        return render_template("error.html", message="The requested trip is not available."), 404
    return render_template("trip_detail.html", trip=trip, items=trip.itinerary_items)


@app.route("/trips/<int:trip_id>/itinerary/new", methods=("GET", "POST"))
@login_required
def add_itinerary_item(trip_id):
    trip = owned_trip_or_none(trip_id)
    if trip is None:
        return render_template("error.html", message="The requested trip is not available."), 404

    form = ItineraryForm()
    if form.validate_on_submit():
        item = ItineraryItem(
            trip_id=trip.id,
            item_type=form.item_type.data,
            item_datetime=datetime.fromisoformat(form.item_datetime.data),
            description=sanitize_text(form.description.data),
        )
        db.session.add(item)
        db.session.commit()
        flash("Itinerary item added.", "success")
        return redirect(url_for("trip_detail", trip_id=trip.id))
    return render_template("itinerary_form.html", trip=trip, form=form)


@app.errorhandler(CSRFError)
def handle_csrf_error(_error):
    return render_template(
        "error.html", message="The form expired or was invalid. Please try again."
    ), 400


@app.errorhandler(HTTPException)
def handle_http_error(error):
    if error.code == 404:
        return render_template("error.html", message="The requested page was not found."), 404
    app.logger.warning("HTTP error %s: %s", error.code, error.description)
    return render_template("error.html", message="The request could not be completed."), error.code


@app.errorhandler(Exception)
def handle_unexpected_error(error):
    if isinstance(error, SQLAlchemyError):
        db.session.rollback()
    app.logger.exception("Unhandled application error", exc_info=error)
    return render_template(
        "error.html", message="Something went wrong. Please try again later."
    ), 500


with app.app_context():
    db.create_all()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=False,
    )