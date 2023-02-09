#!/usr/bin/env python3
""" Module of Users views
"""
from api.v1.views import app_views
from flask import abort, jsonify, request, make_response
from os import getenv
from models.user import User
from typing import TypeVar, List


@app_views.route('/auth_session/login', methods=['POST'], strict_slashes=False)
def login():
    """ Auth session Login

        Return:
            Sessioned with credentials
    """
    email = request.form.get('email')

    if not email:
        return make_response(jsonify({"error": "email missing"}), 400)

    passwd = request.form.get('password')
    if not passwd:
        return make_response(jsonify({"error": "password missing"}), 400)

    exist_user = User.search({"email": email})

    if len(exist_user) == 0:
        return jsonify({"error": "no user found for this email"}), 404

    from api.v1.app import auth
    for user in exist_user:
        if (user.is_valid_password(passwd)):
            session_id = auth.create_session(user.id)
            SESSION_NAME = getenv('SESSION_NAME')
            response = make_response(user.to_json())
            response.set_cookie(SESSION_NAME, session_id)
            return response

    return make_response(jsonify({"error": "wrong password"}), 401)


@app_views.route('/auth_session/logout',
                 methods=['DELETE'], strict_slashes=False)
def logout():
    """ Logout of the session

        Return:
            Logout session
    """
    from api.v1.app import auth
    isdestroy = auth.destroy_session(request)

    if isdestroy is False:
        abort(404)

    return jsonify({}), 200
