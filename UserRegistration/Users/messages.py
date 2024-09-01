#==========================
# Responses
#==========================

# Generate Code
# ------------------------
def code_sent_message(code):
    return {
        "verification_code": code,
    }


def unavailable_server():
    return {"error": "Service is temporarily unavailable, please try again later."}
    # (check redis-celery-docker or Invalid input(cache is empty.)
    

# User Verification 
# ------------------------
def is_expected_code(code, expected_code):
    return (str(code) == str(expected_code))


def valid_code_message():
    return{"message": "Code verified. Proceed to registration."}


def code_expiration_message():
    return {"message": "Verification code is expired."}


def invalid_code_message(attempts):
    return {
        "error": "Invalid verification code.",
        "attempts": attempts
    }


def locked_account_message(attempts):
    return {
        "error": "Account is locked. Please try again later.",
        "attempts": attempts
    }


# User Registration 
# ------------------------
def code_expiration_message():
    return {"message": "Verification code is expired.",}

    
def phone_required_message():
    return {"error": "Phone number is required."}


# User Login 
# ------------------------
def is_user_authenticated(user):
    return (user is not None)


def invalid_user_message(attempts):
    return {
        "error": "Invalid phone number or password.",
        "attempts": attempts
    }


def login_successful_message():
    return {"message": "Login successful."}
    

def already_logged_in_message():
    return {"error": "This user is already logged in."}


def missing_request():
    return {"error":"Request context is missing."}


def authentication_failed():
    return {"detail": "Authentication failed."}


# User logout 
# ------------------------
def user_logout_message():
    return {"message": "Logout successful"}


def user_not_auth_message():
    return {"error": "User does not authenticated."}
