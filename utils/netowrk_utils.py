from flask import request

def get_user_ip():
    """Get the user's IP address from the request object."""
    return request.remote_addr

def get_browser_details():
    """Get the user's browser details from the request headers."""
    user_agent = request.headers.get('User-Agent', 'Unknown Browser')
    return user_agent
