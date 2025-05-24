import html
import re

def sanitize_string(input_str: str) -> str:
    """
    Sanitize a string input by escaping HTML entities and removing potentially dangerous characters.
    This helps prevent Cross-Site Scripting (XSS) attacks by neutralizing HTML tags.
    """
    if not input_str:
        return input_str
    # Escape HTML entities to prevent XSS
    escaped_str = html.escape(input_str)
    # Remove control characters and other potentially dangerous characters
    sanitized_str = re.sub(r'[\x00-\x1f\x7f<>]', '', escaped_str)
    return sanitized_str

def sanitize_username(username: str) -> str:
    """
    Sanitize username by allowing only alphanumeric characters and underscores.
    This prevents injection attacks by restricting allowed characters.
    """
    if not username:
        return username
    sanitized = re.sub(r'[^a-zA-Z0-9_]', '', username)
    return sanitized

def sanitize_email(email: str) -> str:
    """
    Basic sanitization for email input.
    Removes spaces and control characters to ensure valid email format.
    """
    if not email:
        return email
    # Remove spaces and control characters
    sanitized = re.sub(r'\s+', '', email)
    return sanitized

def sanitize_account_number(account_number: str) -> str:
    """
    Sanitize account number by allowing only digits.
    Ensures account numbers are numeric and prevents injection.
    """
    if not account_number:
        return account_number
    sanitized = re.sub(r'[^0-9]', '', account_number)
    return sanitized
