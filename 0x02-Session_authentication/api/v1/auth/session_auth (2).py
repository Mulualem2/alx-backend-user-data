#!/usr/bin/env python3
""" Module of Session Auth
"""
from api.v1.auth.auth import Auth
from models.user import User
from typing import Dict, TypeVar
from uuid import uuid4, UUID


class SessionAuth(Auth):
    """ Auth Class """
    user_id_by_session_id: Dict = {}

    def create_session(self, user_id: str = None) -> str:
        """
            Make a new Session and register in the class

            Args:
                user_id: Identificator of the user_id

            Return:
                Session ID
        """
        if user_id is None or type(user_id) is not str:
            return None

        session_id: str = str(uuid4())
        self.user_id_by_session_id[session_id] = user_id

        return session_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """
            Make a user ID based in session id

            Args:
                session_id: String of the session

            Return:
                User ID
        """
        if session_id is None or type(session_id) is not str:
            return None

        user_id: str = self.user_id_by_session_id.get(session_id)

        return user_id

    def current_user(self, request=None):
        """
            Take the session cookie and the user id
            and show the user

            Args:
                request: Look the request

            Return:
                User instance based in cooikie
        """
        session_id: str = self.session_cookie(request)
        user_id: str = self.user_id_for_session_id(session_id)
        user: TypeVar('User') = User.get(user_id)

        return user

    def destroy_session(self, request=None):
        """ Destroy the auth session if this

        Return:
            Destuction
        """
        if request is None:
            return False

        session_id: str = self.session_cookie(request)

        if session_id is None:
            return False

        user_id: str = self.user_id_for_session_id(session_id)

        if user_id is None:
            return False

        try:
            del self.user_id_by_session_id[session_id]
        except Exception:
            pass

        return True
