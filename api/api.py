import hashlib
import sqlite3
from datetime import timedelta, datetime
from functools import wraps
import re
from flask import g, request, abort, render_template, redirect, session, url_for, flash
from flask_api import FlaskAPI
from flask_cors import CORS
import phonenumbers
from validate_email import validate_email
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, IntegerField, DateField
from wtforms.fields.html5 import DateTimeLocalField
from wtforms.validators import DataRequired
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

api.permanent_session_lifetime = timedelta(minutes=120)  # La session dure 2 heures


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

def trip(trip_id, driver, passengers, departure_date, arrival_date, origin, destination, cost, places_count,
         places_total):
    return {
        'trip_id': trip_id,
        'driver': driver,
        'passengers': passengers,
        'departure_date': departure_date,
        'arrival_date': arrival_date,
        'origin': origin,
        'destination': destination,
        'cost': cost,
        'places_count': places_count,
        'places_total': places_total,

    }


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


# Fonction de hashage pour les passwords

def encrypt_string(hash_string):
    sha_signature = \
        hashlib.sha256(hash_string.encode()).hexdigest()

    return sha_signature


# Fonction de validation de l'username

def conditions_username(username):
    # On récupère la liste des usernames

    temp = query_db('select username from user')

    for i in range(len(temp)):
        temp[i] = temp[i][0]

    if blank(username) > 64:

        abort(400, "La longueur maximale du nom est 64 caractères")

    elif blank(username) < 4:

        abort(400, "La longueur minimale du nom est 4 caractères (espaces exclus)")

    elif '@' in username:

        abort(400, "@ est interdit dans la définition d'un username")

    elif username in temp:

        abort(400, "L'username existe déjà")

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


# Fonction de vérification de nombres dans une string

def hasNumbers(inputString):
    return bool(re.search(r'\d', inputString))


# Fonction de validation d'une ville

def condition_city(city):
    if hasNumbers(city):
        abort(400, 'Une ville ne doit pas contenir de nombres')
    else:
        pass


# Fonction de validation du cardNumber

def condition_cardNumber(cardNumber):
    regex = re.compile("([0-9][0-9][0-9][0-9])\ ([0-9][0-9][0-9][0-9])\ ([0-9][0-9][0-9][0-9])\ ([0-9][0-9][0-9][0-9])")
    search = regex.search(cardNumber)
    if search is not None:

        if search.group(0) != cardNumber:
            abort(400, 'Le numéro saisi est invalide')

    else:
        abort(400, 'Le numéro saisi est invalide')


# Fonction de validation de la date d'expiration

def condition_expireDate(expireDate):
    regex = re.compile("([0-9][0-9])\/([0-9][0-9])")
    search = regex.search(expireDate)
    if search is not None:

        if search.group(0) == expireDate and 1 <= int(expireDate[0:2]) <= 12 and (int(expireDate[3:5]) > int(
                str(datetime.now().year)[2:4]) or (int(expireDate[3:5])== int(
                str(datetime.now().year)[2:4]) and int(expireDate[0:2])>= int(datetime.now().month))):
            pass
        else:
            abort(400, "La date d'expiration est invalide")

    else:
        abort(400, "La date d'expiration est invalide")


# Fonction de validation du cryptogramme

def condition_cryptogram(cryptogram):
    regex = re.compile("([0-9]+)")
    search = regex.search(cryptogram)
    if search is not None:

        if len(cryptogram) != 3 and len(cryptogram) != 4:
            abort(400, 'Le cryptogramme est invalide')
    else:
        abort(400, 'Le cryptogramme est invalide')

# Fonction de validation du titulaire de la carte

def condition_owner(owner):
    regex=re.compile("([A-Z]+)\ ([A-Z]+)")
    search = regex.search(owner)
    if search is not None:
        if search.group(0)!=owner:
            abort(400,'Le nom du titulaire est invalide')
        else:
            pass
    else:
        abort(400,'Le nom du titulaire est invalide')


# Décorateur d'authentification

def logged_in(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            if not session['username'] and not session['_id']:

                return redirect(url_for('login'))
            else:
                return f(*args, **kwargs)
        except KeyError:
            return redirect(url_for('login'))

    return decorated_function


# Routings d'accueil

@api.route("/")
def welcome():
    return redirect(url_for('login'))


@api.route("/index.html")
@logged_in
def index():
    return render_template("index.html")


# Routing d'authentification

@api.route('/login.html', methods=['GET', 'POST'])
def login():
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

                    # Connexion effectuée avec succès

                    id = query_db('select user_id from user where username=?',
                                  [username], one=True)[0]

                    session['_id'] = id

                    session['username'] = username


            else:

                abort(404, 'Username absent dans la base')

        except():

            abort(500)

        else:
            return redirect(url_for('index'))

    return render_template('login.html', title='Log In', form=form)


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')


# Routing de création de trip

@api.route("/trip_create.html", methods=['GET', 'POST'])
@logged_in
def trip_create():
    form = TripForm()

    if form.validate_on_submit():

        result = request.form
        driver = session['username']

        origin = result['origin']
        condition_city(origin)
        destination = result['destination']
        condition_city(destination)
        departure_date = result['departure_date']
        arrival_date = result['arrival_date']
        now = datetime.today().strftime('%Y-%m-%dT%H:%M')

        if departure_date > arrival_date:
            abort(400, "La date de départ doit être antérieure à la date d'arrivée")
        elif departure_date < now or arrival_date < now:
            abort(400, "Les dates doivent correspondre ou être ultérieures à la date d'aujourd'hui ")
        else:
            pass

        cost = 5
        places_total = result['places_total']

        try:

            # Création du trip

            insert_trip = query_db(
                'insert into trip(driver,departure_date,arrival_date,origin,destination,cost,places_count,places_total,passengers) VALUES(?,?,?,?,?,?,?,?,?)',
                [driver, departure_date, arrival_date, origin, destination, cost, int(places_total),
                 int(places_total), ''],
                change=True)

        except():

            abort(500)

        else:
            flash('Trip créé avec succès')
            flash('Cliquez sur My Trips')

    return render_template("trip_create.html", title='Create a trip', form=form)


class TripForm(FlaskForm):
    origin = StringField('Origin', validators=[DataRequired()])
    destination = StringField('Destination', validators=[DataRequired()])
    departure_date = DateTimeLocalField('Departure Date', validators=[DataRequired()], format='%Y-%m-%dT%H:%M')
    arrival_date = DateTimeLocalField('Arrival Date', validators=[DataRequired()], format='%Y-%m-%dT%H:%M')
    places_total = IntegerField('Total Places', validators=[DataRequired()])
    submit = SubmitField('Add Trip')


# Routing de recherche de trip

@api.route("/trip_search.html", methods=['GET', 'POST'])
@logged_in
def trip_search():
    form = TripSearchForm()

    if form.validate_on_submit():

        result = request.form
        origin = result['origin']
        condition_city(origin)
        destination = result['destination']
        condition_city(destination)
        departure_date = result['departure_date']
        places_count = int(result['places_count'])

        if places_count <= 0:
            abort(400, 'Le nombre de places est invalide')

        try:
            trips = api_trip()
            search = []
            for t in trips:
                if (t['origin']== origin) and (t['destination'] == destination) and (
                        departure_date in t['departure_date']) and (places_count <= t['places_count']):
                    search.append(t)

        except():
            abort(500)

        else:
            return render_template("trip_search_result.html", title='Trip Search Result', trips=search)

    return render_template("trip_search.html", title='Search Trip', form=form)


class TripSearchForm(FlaskForm):
    origin = StringField('Origin', validators=[DataRequired()])
    destination = StringField('Destination', validators=[DataRequired()])
    departure_date = DateField('Departure Date', validators=[DataRequired()], format='%Y-%m-%d')
    places_count = IntegerField('Places', validators=[DataRequired()])
    submit = SubmitField('Search Trip')


# Routing de recherche d'user

@api.route("/user_search.html", methods=['GET', 'POST'])
@logged_in
def user_search():
    form = UserSearchForm()

    if form.validate_on_submit():

        result = request.form
        username = result['username']

        try:
            users = api_users()
            search = []
            for u in users:
                if u['username'] == username:
                    search.append(u)

            if len(search) == 1:
                search = search[0]

        except():
            abort(500)

        else:
            return render_template("user_search_result.html", title="User Search Result", user=search)

    return render_template("user_search.html", title='Search User', form=form)


class UserSearchForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    submit = SubmitField('Search User')


# Routing d'inscription

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

            # Création de l'user

            insert_user = query_db(
                'insert into user(username,email,password,phone,authorized,forbiddens) VALUES(?,?,?,?,?,?)',
                [username, email, password, phone, authorized, forbiddens], change=True)

        except():

            abort(500)

        else:
            flash('User créé avec succès')
            flash('Cliquez sur Log In')

    return render_template("signup.html", title='Sign Up', form=form)


class SignupForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired()])
    phone = StringField('Phone', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    authorized = StringField('Authorized')
    forbiddens = StringField('Forbiddens')
    submit = SubmitField('Sign Up')


# Déconnexion

@api.route('/logout')
@logged_in
def logout():
    session.pop('_id', None)
    session.pop('username', None)
    return redirect(url_for('index'))


# Liste des users

def api_users():
    users = query_db('select * from user order by user_id')

    for i in range(len(users)):
        users[i] = user(users[i][0], users[i][1], users[i][2], users[i][3], users[i][4], users[i][5],
                        users[i][6])

    return users


# Profil de l'user connecté

def profil():
    username = session['username']
    infos = query_db('select * from user where username=?', [username], one=True)
    return user(infos[0], infos[1], infos[2], infos[3], infos[4], infos[5], infos[6])


# Profil de l'user

@api.route('/user_profile.html')
@logged_in
def user_profile():
    profile = profil()
    return render_template("user_profile.html", title='User Profile', profile=profile)


# Liste des trips

def api_trip():
    trips = query_db('select * from trip order by trip_id')

    for i in range(len(trips)):
        trips[i] = trip(trips[i][0], trips[i][1], trips[i][2].split('|'), trips[i][3], trips[i][4], trips[i][5],
                        trips[i][6], trips[i][7], trips[i][8], trips[i][9])

    return trips


# Trips de l'user en cours

@api.route('/mytrips.html')
@logged_in
def my_trips():
    all_trips = api_trip()
    driver = []
    passenger = []
    for t in all_trips:
        if t['driver'] == session['username']:
            driver.append(t)
        if session['username'] in t['passengers']:
            passenger.append(t)
        else:
            pass

    return render_template("mytrips.html", title="My Trips", trips_driver=driver,trips_passenger=passenger)


# Paiement

@api.route("/checkout.html%<int:trip_id>", methods=['GET', 'POST'])
@logged_in
def checkout(trip_id):
    infos = query_db('select * from trip where trip_id=?', [trip_id], one=True)

    try:

        if not infos:

            abort(404, 'Trip not found with the given trip_id')

        else:

            book_trip = trip(infos[0], infos[1], infos[2], infos[3], infos[4], infos[5], infos[6],
                             infos[7], infos[8], infos[9])

    except():

        abort(500)

    else:

        if book_trip['places_count']<=0:
            abort(404)

        else:
            pass

    form = CheckoutForm()

    if form.validate_on_submit():
        result = request.form
        owner = result['username']
        condition_owner(owner)
        cardNumber = result['cardNumber']
        condition_cardNumber(cardNumber)
        expireDate = result['expireDate']
        condition_expireDate(expireDate)
        cryptogram = result['cryptogram']
        condition_cryptogram(cryptogram)
        passenger = "|"+session['username']



        try:

            update_trip = query_db(
                'update trip set passengers=passengers || ?,places_count=places_count-1 where trip_id=?',
                [passenger, trip_id], change=True)

        except():

            abort(500)

        else:
            return redirect(url_for('my_trips'))

    return render_template("checkout.html", title='Check Out', form=form, trip=book_trip)


class CheckoutForm(FlaskForm):
    username = StringField('Card Owner',validators=[DataRequired()])
    cardNumber = StringField('Card Number', validators=[DataRequired()])
    expireDate = StringField('Expire Date', validators=[DataRequired()])
    cryptogram = StringField('Cryptogram', validators=[DataRequired()])
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


# Nom de la base de données

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
