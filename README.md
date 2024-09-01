# Phone Number Django Authentication

This project provides a phone number-based authentication system for Django applications, allowing users to log in using their phone number and a verification code. The project leverages Docker, Redis, and Django's caching framework. Note that the actual SMS sending functionality is not implemented.

## Features

- **Phone Number Authentication:** Users register and log in with their phone numbers.
- **OTP Verification:** One-Time Password (OTP) verification for secure authentication.
- **Account Locking:** If a user enters the wrong password three times, their account will be locked for one hour.
- **Integration with Django:** Seamless integration with Django's authentication system.
- **Dockerized Setup:** Easy deployment with Docker.
- **Redis, Celery and Caching:** Efficient OTP management with Redis and Django caching.

## API Endpoints

- `generate-code/` - Generate a verification code.
- `user-verification/` - Verify the user's OTP.
- `user-register/` - Register a new user.
- `user-login/` - Log in a user.
- `user-logout/` - Log out the user.

## Installation

1. **Clone the repository:**

    ```bash
    git clone https://github.com/HouraHashemi/Phone-Number-Django-Authentication.git
    cd Phone-Number-Django-Authentication
    ```

2. **Set up Docker and Redis:**

    ```bash
    docker run -d -p 6379:6379 redis
    docker exec -it containerID redis-cli
    ```

3. **Set up Celery:**

    ```bash
    pip install celery
    celery -A ProjectName worker --loglevel=info
    ```

## Customization

You can customize the following components:

- **OTP Logic:** Modify OTP generation and validation.
- **SMS Backend:** Integrate with your preferred SMS gateway for sending OTPs (note: not implemented).
- **User Profile:** Extend the user model with additional fields.

## Contributing

1. Fork the repository.
2. Create a new branch for your feature or bugfix.
3. Submit a pull request with a detailed explanation.

## Acknowledgments

- [Django](https://www.djangoproject.com/) - The web framework used.
- [Redis](https://redis.io/) - For caching and efficient OTP management.

