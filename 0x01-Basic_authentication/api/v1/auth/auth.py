#!/usr/bin/env python3
"""
Manage the API authentication.
"""
from flask import request
from typing import List, TypeVar


class Auth:
    """
    Auth class
    """
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        require_auth function
        """
        if path is None or excluded_paths is None or not excluded_paths:
            return True
        if path in excluded_paths or path[-1] != '/' and path + '/'\
                in excluded_paths:
            return False
        for p in excluded_paths:
            if p.endswith('*') and path.startswith(p[:-1]):
                return False
        return True

    def authorization_header(self, request=None) -> str:
        """
        authorization_header function
        """
        if not request or not request.headers or\
                not request.headers.get('Authorization'):
            return None
        return request.headers.get('Authorization')

    def current_user(self, request=None) -> TypeVar('User'):
        """
        current_user function
        """
        return None
