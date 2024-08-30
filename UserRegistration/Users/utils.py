
import random

def generate_temp_password():
    return random.randint(100000, 999999)


# Responses
#--------------------

# Generate Code

def code_sent_message(code):
    response = {
        "verification_code": code,
    }
    return response


def unavailable_server():
    response = {
        "error": "Service is temporarily unavailable, please try again later.",
    }
    return response
#--------------------

