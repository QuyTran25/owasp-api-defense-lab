import os
import connexion
from flask import jsonify
from flask_sqlalchemy import SQLAlchemy
from connexion.exceptions import ProblemException

vuln_app = connexion.App(__name__, specification_dir='./openapi_specs')

SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(vuln_app.app.root_path, 'database/database.db')
vuln_app.app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
vuln_app.app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# State B integration: Kong's JWT plugin verifies tokens issued by VAmPI.
# The signing secret is deployment-specific and must never be committed.
JWT_SECRET = os.getenv('VAMPI_JWT_SECRET')
if not JWT_SECRET:
    raise RuntimeError('VAMPI_JWT_SECRET must be set; refusing to use an insecure default JWT secret.')

vuln_app.app.config['SECRET_KEY'] = JWT_SECRET
vuln_app.app.config['JWT_ISSUER'] = os.getenv('VAMPI_JWT_ISSUER', 'vampi-state-b')
# start the db
db = SQLAlchemy(vuln_app.app)

def custom_problem_handler(error):
    # Custom error handler for clarity in structure
    response = jsonify({
        "status": "fail",
        "message": getattr(error, "detail", "An error occurred"),
    })
    response.status_code = error.status
    return response
vuln_app.add_error_handler(ProblemException, custom_problem_handler)

vuln_app.add_api('openapi3.yml')
