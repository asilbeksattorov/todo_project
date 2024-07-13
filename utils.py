from hashlib import sha256


class Response:
    def __init__(self, data: str, status_code: int):
        self.data = data
        self.status_code = status_code


def hash_password(raw_password: str) -> str:
    """
    Hashes the provided raw password using SHA-256 algorithm.

    Args:
        raw_password (str): The plaintext password to be hashed.

    Returns:
        str: The hashed password.
    """
    return sha256(raw_password.encode()).hexdigest()


def match_password(raw_password: str, encoded_password: str) -> bool:
    """
    Compares the provided raw password with the encoded password.

    Args:
        raw_password (str): The plaintext password to be checked.
        encoded_password (str): The hashed password to be compared against.

    Returns:
        bool: True if the raw password matches the encoded password, False otherwise.
    """
    return hash_password(raw_password) == encoded_password


def register_user(username: str, raw_password: str) -> Response:
    """
    Registers a new user with the provided username and password.

    Args:
        username (str): The username for the new user.
        raw_password (str): The plaintext password for the new user.

    Returns:
        Response: A response object with the registration status and any relevant data.
    """
    # Perform registration logic here
    # For example, store the hashed password in a database
    hashed_password = hash_password(raw_password)
    # Additional registration logic...

    return Response("Registration successful", 201)