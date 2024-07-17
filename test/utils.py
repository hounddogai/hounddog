import logging

from sentry_sdk import capture_exception as capture

username = "username"
email = "email"
ssn = "ssn"
age = 20
first_name = "first_name"
last_name = "last_name"
credit_score = 800


def do_something():
    capture(
        Exception(username),
        username,
        {
            "name": username,
            "email": email,
            "ssn": ssn,
            "age": age,
            "first_name": first_name,
            "last_name": last_name,
            "credit_score": credit_score,
            "foo": age,
        },
        ssn,
        "{}".format(username),
        "this is username" + username,
    )


def do_something_else():
    try:
        logging.info(
            username,
        )
    except Exception as e:
        capture(e)
        raise e


logging.info(
    first_name
)
