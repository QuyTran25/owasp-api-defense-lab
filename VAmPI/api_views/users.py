import re
import jsonschema
import jwt

from config import db, vuln_app
from api_views.json_schemas import *
from flask import jsonify, Response, request, json
from models.user_model import User
from app import vuln


def error_message_helper(msg):
    if isinstance(msg, dict):
        return '{ "status": "fail", "message": "' + msg['error'] + '"}'
    else:
        return '{ "status": "fail", "message": "' + msg + '"}'


def unauthorized_response():
    return Response(error_message_helper("Invalid token. Please log in again."),
                    401, mimetype="application/json")


def forbidden_response():
    return Response(error_message_helper("You are not authorized to perform this action."),
                    403, mimetype="application/json")


def get_authenticated_user(auth_header):
    """Resolve a verified JWT subject to a current database user.

    Kong's JWT/ACL plugins are boundary controls. Authorization decisions here
    deliberately use the application database so a shared Kong Consumer or an
    untrusted JWT role claim cannot grant per-user or admin access.
    """
    payload = token_validator(auth_header)
    if "error" in payload:
        return None, unauthorized_response()

    subject = payload.get('sub')
    if not isinstance(subject, str) or not subject:
        return None, unauthorized_response()

    user = User.query.filter_by(username=subject).first()
    if not user:
        return None, unauthorized_response()

    return user, None


def get_admin_user(auth_header):
    user, error = get_authenticated_user(auth_header)
    if error is not None:
        return None, error
    if not user.admin:
        return None, forbidden_response()
    return user, None


def get_all_users():
    user, error = get_admin_user(request.headers.get('Authorization'))
    if error is not None:
        return error
    return_value = jsonify({'users': User.get_all_users()})
    return return_value


def me():
    user, error = get_authenticated_user(request.headers.get('Authorization'))
    if error is not None:
        return error
    responseObject = {
        'status': 'success',
        'data': user.profile_dto()
    }
    return Response(json.dumps(responseObject), 200, mimetype="application/json")
        

def get_by_username(username):
    user, error = get_authenticated_user(request.headers.get('Authorization'))
    if error is not None:
        return error
    if not user.admin and username != user.username:
        return forbidden_response()

    # Use an ORM equality lookup so the path parameter is never interpreted as
    # SQL and the authorization decision stays independent of lab-mode flags.
    target_user = User.query.filter_by(username=username).first()
    if not target_user:
        return Response(error_message_helper("User not found"), 404, mimetype="application/json")
    return jsonify(target_user.profile_dto())


def register_user():
    request_data = request.get_json(silent=True)
    try:
        jsonschema.validate(request_data, register_user_schema)
    except jsonschema.exceptions.ValidationError as exc:
        return Response(error_message_helper(exc.message), 400, mimetype="application/json")

    user = User.query.filter_by(username=request_data['username']).first()
    if user:
        return Response(error_message_helper("User already exists. Please Log in."), 200, mimetype="application/json")

    # Public registration creates only a standard account. Privileged roles are
    # assigned through a separate administrative process.
    user = User(username=request_data['username'], password=request_data['password'],
                email=request_data['email'])
    db.session.add(user)
    db.session.commit()

    responseObject = {
        'status': 'success',
        'message': 'Successfully registered. Login to receive an auth token.'
    }
    return Response(json.dumps(responseObject), 200, mimetype="application/json")


def login_user():
    request_data = request.get_json(silent=True)

    try:
        # validate the data are in the correct form
        jsonschema.validate(request_data, login_user_schema)
        # fetching user data if the user exists
        user = User.query.filter_by(username=request_data.get('username')).first()
        if user and request_data.get('password') == user.password:
            auth_token = user.encode_auth_token(user.username)
            responseObject = {
                'status': 'success',
                'message': 'Successfully logged in.',
                'auth_token': auth_token
            }
            return Response(json.dumps(responseObject), 200, mimetype="application/json")
        if vuln:  # Password Enumeration
            if user and request_data.get('password') != user.password:
                return Response(error_message_helper("Password is not correct for the given username."), 200,
                                mimetype="application/json")
            elif not user:  # User enumeration
                return Response(error_message_helper("Username does not exist"), 200, mimetype="application/json")
        else:
            if (user and request_data.get('password') != user.password) or (not user):
                return Response(error_message_helper("Username or Password Incorrect!"), 200,
                                mimetype="application/json")
    except jsonschema.exceptions.ValidationError as exc:
        return Response(error_message_helper(exc.message), 400, mimetype="application/json")
    except:
        return Response(error_message_helper("An error occurred!"), 200, mimetype="application/json")


def token_validator(auth_header):
    if auth_header:
        try:
            auth_token = auth_header.split(" ")[1]
        except:
            auth_token = ""
    else:
        auth_token = ""
    if auth_token:
        # if auth_token is valid we get back the username of the user
        return User.decode_auth_token(auth_token)
    else:
        return {'error': 'Invalid token. Please log in again.'}


def update_email(username):
    request_data = request.get_json(silent=True)
    try:
        jsonschema.validate(request_data, update_email_schema)
    except jsonschema.exceptions.ValidationError:
        return Response(error_message_helper("Please provide a proper JSON body."), 400, mimetype="application/json")
    user, error = get_authenticated_user(request.headers.get('Authorization'))
    if error is not None:
        return error
    if username != user.username:
        return forbidden_response()

    if vuln:  # Regex DoS
        match = re.search(
            r"^([0-9a-zA-Z]([-.\w]*[0-9a-zA-Z])*@{1}([0-9a-zA-Z][-\w]*[0-9a-zA-Z]\.)+[a-zA-Z]{2,9})$",
            str(request_data.get('email')))
        if not match:
            return Response(error_message_helper("Please Provide a valid email address."), 400,
                            mimetype="application/json")
    else:
        regex = r'^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$'
        if not re.search(regex, request_data.get('email')):
            return Response(error_message_helper("Please Provide a valid email address."), 400,
                            mimetype="application/json")

    user.email = request_data.get('email')
    db.session.commit()
    responseObject = {
        'status': 'success',
        'data': {
            'username': user.username,
            'email': user.email
        }
    }
    return Response(json.dumps(responseObject), 204, mimetype="application/json")


def update_password(username):
    request_data = request.get_json(silent=True)
    user, error = get_authenticated_user(request.headers.get('Authorization'))
    if error is not None:
        return error
    if username != user.username:
        return forbidden_response()
    if not request_data or not request_data.get('password'):
        return Response(error_message_helper("Malformed Data"), 400, mimetype="application/json")

    user.password = request_data.get('password')
    db.session.commit()
    responseObject = {
        'status': 'success',
        'Password': 'Updated.'
    }
    return Response(json.dumps(responseObject), 204, mimetype="application/json")


def delete_user(username):
    user, error = get_admin_user(request.headers.get('Authorization'))
    if error is not None:
        return error
    if username == user.username:
        return forbidden_response()
    if bool(User.delete_user(username)):
        responseObject = {
            'status': 'success',
            'message': 'User deleted.'
        }
        return Response(json.dumps(responseObject), 200, mimetype="application/json")
    return Response(error_message_helper("User not found!"), 404, mimetype="application/json")
