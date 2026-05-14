# SAFE: flask-sqlalchemy-uri-hardcoded — database URI loaded from environment variable
# Rule: FlaskSqlAlchemyUriHardcoded | CWE-798 | Expected: TrueNegative

import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)

# SAFE: database URI loaded from environment variable; credentials never hardcoded
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['DATABASE_URL']
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)

if __name__ == '__main__':
    app.run()
