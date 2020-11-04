import hashlib
import sqlite3
from flask import jsonify, g, request, abort, render_template, redirect
from flask_api import FlaskAPI, status
from flask_cors import CORS
import phonenumbers
from validate_email import validate_email
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, IntegerField, DateField
from wtforms.validators import DataRequired, Email
import win32api

# Settings

# set FLASK_APP=api.py
# set FLASK_ENV=development
# set FLASK_DEBUG=1

# Initialisation de l'api

api = FlaskAPI(__name__)
CORS(api)

# Configuration de l'api

api.config['SECRET_KEY'] = 'ec3f0831f0978bdc130ebba668551da9afb8740938af64999364262d4ce06d71'


# JSON user

def user(user_id, username, email, password, phone, authorized, forbiddens):
    return {'user_id': user_id,
            'username': username,
            'email': email,
            'password': password,
            'phone': phone,
            'authorized': authorized,
            'forbiddens': forbiddens
            }


# JSON trip

def trip(trip_id, driver, passengers, departure_date, arrival_date, origin, destination, cost, is_full):
    return {
        'trip_id': trip_id,
        'driver': driver,
        'passengers': passengers,
        'departure_date': departure_date,
        'arrival_date': arrival_date,
        'origin': origin,
        'destination': destination,
        'cost': cost,
        'is_full': is_full

    }

# Fonction de hashage pour les passwords

def encrypt_string(hash_string):
    sha_signature = \
        hashlib.sha256(hash_string.encode()).hexdigest()

    return sha_signature


# Fonction de validation de l'username

def conditions_username(username):
    if blank(username) > 64:

        abort(400, "La longueur maximale du nom est 64 caractères")

    elif blank(username) < 4:

        abort(400, "La longueur minimale du nom est 4 caractères (espaces exclus)")

    elif '@' in username:

        abort(400, "@ est interdit dans la définition d'un username")

    else:
        pass


# Fonction de validation de l'email

def conditions_email(email):
    # On récupère la liste des emails

    temp = query_db('select email from user')

    for i in range(len(temp)):
        temp[i] = temp[i][0]

    # Check the email validations

    if validate_email(email) and not_blank(email):

        if len(email) > 32:

            abort(400, "La longueur maximale de l'email est 32 caractères")

        elif len(email) < 6:

            abort(400, "La longueur minimale de l'email est 6 caractères")

        elif email in temp:

            abort(400, "L'email est déjà dans la base de données")

        else:
            pass

    else:

        abort(400, "L'email est invalide")


# Fonction de validation du phone

def conditions_phone(phone):
    try:

        temp = phonenumbers.parse(number=phone, region=None)

        if not (phonenumbers.is_valid_number(temp)):
            abort(400, "Le numéro de téléphone est invalide")


    except phonenumbers.phonenumberutil.NumberParseException:

        abort(400, "Le numéro de téléphone n'a pas été correctement parsé")


# Fonction de validation du password

def conditions_password(password):
    if len(password) > 64:

        abort(400, "La longueur maximale du password est 64 caractères")

    elif len(password) < 6:

        abort(400, "La longueur minimale du password est 6 caractères")

    else:

        pass


# Routings d'accueil

@api.route("/")
def welcome():
    return index()


@api.route("/index.html")
def index():
    return render_template("index.html")


# Routing d'authentification

@api.route('/login.html', methods=['GET', 'POST'])
def login_form():
    form = LoginForm()

    if form.validate_on_submit():

        result = request.form

        try:

            # On récupère la liste des usernames

            temp = query_db('select username from user')
            for i in range(len(temp)):
                temp[i] = temp[i][0]

            username = result['username']

            password = result['password']

            # Vérification de l'username et du password

            if username in temp:

                test_password = encrypt_string(password)

                correct_password = query_db('select password from user where username=?',
                                            [username], one=True)[0]

                if test_password != correct_password:

                    abort(404, "Password incorrect")

                else:

                    pass  # Connexion effectuée avec succès

            else:

                abort(404, 'Username absent dans la base')

        except():

            abort(500)

        else:
            return redirect('/index.html')

    else:
        pass

    return render_template('login.html', title='Log In', form=form)


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')


@api.route("/trip_create.html", methods=['GET', 'POST'])
def trip_create():
    form = TripForm()

    if form.validate_on_submit():

        result = request.form
        # driver = result['driver']
        departure_date = result['departure_date']
        arrival_date = result['arrival_date']
        origin = result['origin']
        destination = result['destination']
        cost = result['cost']
        is_full = 'False'

        try:

            # Création du trip

            insert_trip = query_db(
                'insert into trip(departure_date,arrival_date,origin,destination,cost,is_full) VALUES(?,?,?,?,?,?)',
                [departure_date, arrival_date, origin, destination, int(cost), is_full], change=True)

            trip_id = query_db('select last_insert_rowid()', one=True)[0]

        except():

            abort(500)

        else:
            win32api.MessageBox(0, 'Trip well created', 'TravelExpress', 0x00001000)

    return render_template("trip_create.html", title='Create a trip', form=form)


class TripForm(FlaskForm):
    origin = StringField('Origin', validators=[DataRequired()])
    destination = StringField('Destination', validators=[DataRequired()])
    cost = IntegerField('Cost', validators=[DataRequired()])
    departure_date = DateField('Departure Date', format='%Y-%m-%d', validators=[DataRequired()])
    arrival_date = DateField('Arrival Date', format='%Y-%m-%d', validators=[DataRequired()])
    submit = SubmitField('Add Trip')


@api.route("/trip_search.html", methods=['GET', 'POST'])
def trip_search():
    form = TripSearchForm()

    if form.validate_on_submit():

        result = request.form
        origin = result['origin']
        destination = result['destination']
        departure_date = result['departure_date']

        try:
            trips = api_trip()
            search = []
            for t in trips:
                if (t['origin'] == origin) and (t['destination'] == destination) and (
                        t['departure_date'] == departure_date):
                    search.append(t)
        except():
            abort(500)

        else:
            return render_template("trip_search_result.html",title='Trip Search Result',trips=trips)

    return render_template("trip_search.html", title='Search Trip', form=form)


class TripSearchForm(FlaskForm):
    origin = StringField('Origin', validators=[DataRequired()])
    destination = StringField('Destination', validators=[DataRequired()])
    departure_date = DateField('Departure Date', validators=[DataRequired()])
    submit = SubmitField('Search Trip')


@api.route("/user_search.html", methods=['GET', 'POST'])
def user_search():
    form = UserSearchForm()

    if form.validate_on_submit():

        result = request.form
        username = result['username']

        try:
            users = api_user()
            search = []
            for u in users:
                if u['username'] == username:
                    search.append(u)

        except():
            abort(500)

        else:
            return render_template("user_search_result.html",title="User Search Result",users=users)
    return render_template("user_search.html", title='Search User', form=form)


class UserSearchForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    submit = SubmitField('Search User')


@api.route("/signup.html", methods=['GET', 'POST'])
def signup_page():
    form = SignupForm()

    if form.validate_on_submit():

        result = request.form

        username = result['username']

        conditions_username(username)

        email = result['email']

        conditions_email(email)

        phone = result['phone']

        conditions_phone(phone)

        password = result['password']

        conditions_password(password)

        password = encrypt_string(password)

        authorized = result['authorized']

        forbiddens = result['forbiddens']

        try:

            # Creation de l'user

            insert_user = query_db(
                'insert into user(username,email,password,phone,authorized,forbiddens) VALUES(?,?,?,?,?,?)',
                [username, email, password, phone, authorized, forbiddens], change=True)

            user_id = query_db('select last_insert_rowid()', one=True)[0]

        except():

            abort(500)

        else:
            win32api.MessageBox(0, 'User créé avec succès', 'TravelExpress', 0x00001000)

    return render_template("signup.html", title='Sign Up', form=form)


class SignupForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired()])
    phone = StringField('Phone', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    authorized = StringField('Authorized')
    forbiddens = StringField('Forbiddens')
    submit = SubmitField('Sign Up')


# Liste des users

def api_user():
    users = query_db('select * from user order by user_id')

    for i in range(len(users)):
        users[i] = user(users[i][0], users[i][1], users[i][2], users[i][3], users[i][4], users[i][5],
                        users[i][6])

    return users


@api.route('/user/<int:user_id>/', methods=['GET', 'PATCH', 'DELETE'])
def api_user_id(user_id):
    try:

        infos = query_db('select * from user where user_id=?', [user_id], one=True)

        if request.method == "GET":


            try:

                if not infos:

                    abort(404, 'User not found with the given user_id')

                else:

                    profil = user(infos[0], infos[1], infos[2], infos[3], infos[4], infos[5], infos[6])

                    return jsonify(profil), status.HTTP_200_OK

            except():

                abort(500)


        elif request.method == "PATCH":

            try:

                # Name

                name = request.data.get('name', None)

                conditions_username(name)

                # Email

                email = request.data.get('email', None)

                if infos[2] != email:

                    conditions_email(email)

                else:

                    pass

                # Phone

                phone = request.data.get('phone', None)

                conditions_phone(phone)

                # Password

                password = request.data.get('password', None)

                if infos[3] != password:

                    conditions_password(password)

                    password = encrypt_string(password)

                else:

                    pass

                # Preferences

                authorized = request.data.get('authorized', None)

                forbiddens = request.data.get('forbiddens', None)

                # Update of the user

                update_user = query_db(
                    'update user set name=?,email=?,password=?,phone=?,authorized=?,forbiddens=? where user_id=?',
                    [name, email, password, phone, authorized, forbiddens, user_id], change=True)

                return user(user_id, name, email, password, phone, authorized, forbiddens), status.HTTP_200_OK


            except():

                abort(500)

        else:  # request.method ='DELETE'

            try:

                # Get the list of user_ids

                liste = query_db('select user_id from user')

                temp = []

                for element in liste:
                    temp += element

                if user_id in temp:

                    delete_user = query_db('delete from user where user_id=?', [user_id], change=True)

                    return {}, status.HTTP_204_NO_CONTENT

                else:

                    abort(404, 'User has already been deleted or does not exist')


            except():

                abort(500)

    except():

        abort(500)


# Liste des trips

def api_trip():
    trips = query_db('select * from trip order by trip_id')

    for i in range(len(trips)):
        trips[i] = trip(trips[i][0], trips[i][1], trips[i][2], trips[i][3], trips[i][4], trips[i][5],
                        trips[i][6], trips[i][7], trips[i][8])

    return trips


@api.route('/trip/<int:trip_id>/', methods=['GET', 'PATCH', 'DELETE'])
def trip_trip_id(trip_id):
    try:

        infos = query_db('select * from trip where trip_id=?', [trip_id], one=True)

        if request.method == "GET":

            try:

                if not infos:

                    abort(404, 'Trip not found with the given trip_id')

                else:

                    profil = trip(infos[0], infos[1], infos[2], infos[3], infos[4], infos[5], infos[6],
                                  infos[7], infos[8])

                    return jsonify(profil), status.HTTP_200_OK

            except():

                abort(500)


        elif request.method == "PATCH":

            try:

                # Driver

                driver = request.data.get('driver', None)

                # Passengers

                passengers = request.data.get('passengers', None)

                # Departure date

                departure_date = request.data.get('departure_date', None)

                # Arrival date

                arrival_date = request.data.get('arrival_date', None)

                # Origin

                origin = request.data.get('origin', None)

                # Destination

                destination = request.data.get('destination', None)

                # Cost

                cost = request.data.get('cost', None)

                # Full

                is_full = request.data.get('is_full', None)

                # Update of the trip

                update_trip = query_db(
                    'update trip set driver=?,passengers=?,departure_date=?,arrival_date=?,origin=?,destination=?,cost=?,is_full=? where user_id=?',
                    [driver, passengers, departure_date, arrival_date, origin, destination, cost, is_full,
                     is_full, trip_id], change=True)

                return trip(trip_id, driver, passengers, departure_date, arrival_date, origin, destination, cost,
                            is_full), status.HTTP_200_OK


            except():

                abort(500)

        else:  # request.method ='DELETE'

            try:

                # Get the list of trip_ids

                liste = query_db('select trip_id from trip')

                temp = []

                for element in liste:
                    temp += element

                if trip_id in temp:

                    delete_user = query_db('delete from trip where trip_id=?', [trip_id], change=True)

                    return {}, status.HTTP_204_NO_CONTENT

                else:

                    abort(404, 'Trip has already been deleted or does not exist')


            except():

                abort(500)

    except():

        abort(500)


@api.route("/checkout.html")
def checkout():
    form = CheckoutForm()
    return render_template("checkout.html", title='Checkout', form=form)

class CheckoutForm(FlaskForm):

    username = StringField('Username', validators=[DataRequired()])
    cardNumber = IntegerField('Card Number', validators=[DataRequired()])
    expireDate = StringField('Expire Date', validators=[DataRequired()])
    cryptogram = IntegerField('Cryptogram', validators=[DataRequired()])
    submit = SubmitField('Confirm Transaction')

# Template Error

def error(e):
    type, message = str(e).split(":")
    return render_template("error.html", type=type, message=message)


# Routings d'erreurs

@api.errorhandler(400)  # Bad Request
def bad_request(e):
    return error(e), 400


@api.errorhandler(401)  # Unauthorized
def unauthorized(e):
    return error(e), 401


@api.errorhandler(403)  # Forbidden
def forbidden(e):
    return error(e), 403


@api.errorhandler(404)  # Resource not found
def resource_not_found(e):
    return error(e), 404


@api.errorhandler(405)  # Method not allowed
def method_not_allowed(e):
    return error(e), 405


@api.errorhandler(500)  # Internal Error Server
def internal_error_server(e):
    return error(e), 500


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


# Requête SQLite

def query_db(query, args=(), one=False, change=False):
    cur = get_db().execute(query, args)
    rv = None
    if change:
        get_db().commit()
    else:
        rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv


# Running de l'api

if __name__ == '__main__':
    api.run(debug=True)
