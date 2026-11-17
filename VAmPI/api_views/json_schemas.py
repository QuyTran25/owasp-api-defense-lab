register_user_schema = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "username": {"type": "string"},
        "password": {"type": "string"},
        "email": {"type": "string"}
    },
    "required": ["username", "password", "email"]
}

login_user_schema = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "username": {"type": "string"},
        "password": {"type": "string"}
    },
    "required": ["username", "password"]
}

update_email_schema = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "email": {"type": "string"}
    },
    "required": ["email"]
}

add_book_schema = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "book_title": {"type": "string"},
        "secret": {"type": "string"}
    },
    "required": ["book_title", "secret"]
}
