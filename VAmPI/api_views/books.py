import jsonschema

from api_views.users import token_validator, error_message_helper
from config import db
from api_views.json_schemas import *
from flask import jsonify, Response, request, json
from models.user_model import User
from models.books_model import Book


def get_all_books():
    return_value = jsonify({'Books': Book.get_all_books()})
    return return_value


def add_new_book():
    request_data = request.get_json()
    try:
        jsonschema.validate(request_data, add_book_schema)
    except:
        return Response(error_message_helper("Please provide a proper JSON body."), 400, mimetype="application/json")
    resp = token_validator(request.headers.get('Authorization'))
    if "error" in resp:
        return Response(error_message_helper(resp), 401, mimetype="application/json")
    else:
        user = User.query.filter_by(username=resp['sub']).first()

        # check if user already has this book title
        book = Book.query.filter_by(user=user, book_title=request_data.get('book_title')).first()
        if book:
            return Response(error_message_helper("Book Already exists!"), 400, mimetype="application/json")
        else:
            newBook = Book(book_title=request_data.get('book_title'), secret_content=request_data.get('secret'),
                           user_id=user.id)
            db.session.add(newBook)
            db.session.commit()
            responseObject = {
                'status': 'success',
                'message': 'Book has been added.'
            }
            return Response(json.dumps(responseObject), 200, mimetype="application/json")


def get_by_title(book_title):
    resp = token_validator(request.headers.get('Authorization'))
    if "error" in resp:
        return Response(error_message_helper(resp), 401, mimetype="application/json")

    # W3-BACKEND-01: enforce object-level authorization at the backend.
    # Kong only authenticates a coarse-grained Consumer; it cannot decide who
    # owns a specific book. Resolve the signed subject to the server-side user
    # record, then apply ownership as part of the database lookup.
    subject = resp.get('sub')
    if not isinstance(subject, str) or not subject:
        return Response(error_message_helper("Invalid token. Please log in again."),
                        401, mimetype="application/json")

    user = User.query.filter_by(username=subject).first()
    if not user:
        # A valid JWT for a deleted/non-existent account is not an authorized
        # principal. Avoid a server error and fail closed.
        return Response(error_message_helper("Invalid token. Please log in again."),
                        401, mimetype="application/json")

    # Default-deny policy, including for administrators: this endpoint returns
    # secret content, so no cross-owner access is granted here. Administrative
    # access, if needed later, must use a separate explicitly-authorized and
    # audited endpoint. Include owner user_id in the query itself; a foreign
    # title therefore has the same 404 result as an absent title.
    book = Book.query.filter_by(book_title=str(book_title), user_id=user.id).first()

    if not book:
        return Response(error_message_helper("Book not found!"), 404, mimetype="application/json")

    responseObject = {
        'book_title': book.book_title,
        'secret': book.secret_content,
        'owner': book.user.username
    }
    return Response(json.dumps(responseObject), 200, mimetype="application/json")
