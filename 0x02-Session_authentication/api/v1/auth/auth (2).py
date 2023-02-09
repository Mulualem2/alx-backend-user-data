#!/usr/bin/env python3
""" Module of auth
"""
from os import getenv
from flask import request
from typing import List, TypeVar


class Auth:
    """ Auth Class """

    def __init__(self):
        """
            Constructor

            Args:
                path: path to authenticate
                excluded_paths: list of excluded path to authenticate
        """

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
            Require the auth

            Args:
                path: path to authenticate
                excluded_paths: list of excluded path to authenticate

            Return:
                True if is authenticated otherwise false
        """
        if path is None or excluded_paths is None or len(excluded_paths) == 0:
            return True

        if path[-1] is not '/':
            path += '/'

        for paths in excluded_paths:
            if paths.endswith('*'):
                if path.startswith(paths[:-1]):
                    return False
            elif path == paths:
                return False

        return True

    def authorization_header(self, request=None) -> str:
        """
            Look the headers

            Args:
                request: Look the autthorization

            Return:
                The authorization header or None
        """
        if request is None:
            return None

        return request.headers.get('Authorization', None)

    def current_user(self, request=None) -> TypeVar('User'):
        """
            Look current user

            Args:
                request: Look the reques user

            Return:
                The user
        """
        return None

    def session_cookie(self, request=None):
        """
            Cookie value

            Args:
                request: Get the cookie session

            Return:
                Cookie session
        """
        if request is None:
            return None

        session_env = getenv('SESSION_NAME', None)
        cookie_sess = request.cookies.get(session_env, None)

        return cookie_sess
