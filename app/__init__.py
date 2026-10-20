from flask import Flask, render_template, url_for
from flask_sqlalchemy import SQLAlchemy
from config import Config

# Initialize Flask and SQLAlchemy 

app = Flask(__name__)
db = SQLAlchemy()

# Load configuration
app.config.from_object(Config)

# Connect app to SQLAlchemy
db.init_app(app)

from app import models
from app.routes import main

app.register_blueprint(main)