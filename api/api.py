import sqlite3

from flask import jsonify,g
from flask_api import FlaskAPI
from flask_cors import CORS


api = FlaskAPI(__name__)
CORS(api)

# Configurations de l'api

api.config['SECRET_KEY'] = 'ec3f0831f0978bdc130ebba668551da9afb8740938af64999364262d4ce06d71'


@api.route("/")
def test():
    user = query_db('select * from user ',[],one=True)
    if user is None:
        print('No such user')
    return "Hello World"

# Routings d'erreurs

@api.errorhandler(400)  # Bad Request
def bad_request(e):
    return jsonify(error=str(e)), 400


@api.errorhandler(401)  # Unauthorized
def unauthorized(e):
    return jsonify(error=str(e)), 401


@api.errorhandler(403)  # Forbidden
def forbidden(e):
    return jsonify(error=str(e)), 403


@api.errorhandler(404)  # Resource not found
def resource_not_found(e):
    return jsonify(error=str(e)), 404


@api.errorhandler(405)  # Method not allowed
def method_not_allowed(e):
    return jsonify(error=str(e)), 405


@api.errorhandler(500)  # Internal Error Server
def internal_error_server(e):
    return jsonify(error=str(e)), 500

# Fonctions de repérage des espaces

def blank(string):
    res = len(string)

    for i in range(len(string)):

        if string[i] == ' ':
            res -= 1

    return res


def not_blank(string):
    boolean = False

    if len(string.split(' ')) == 1:
        boolean = True

    return boolean


DATABASE = 'TravelExpress.db'

# Ouverture de la connexion

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db


# Fermeture de la connexion

@api.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# Requête SQL

def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv


# Running de l'api

if __name__ == '__main__':
    api.run(debug=True)
