from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Sports, Essentials, User
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Catalog"

engine = create_engine('sqlite:///sports_db.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

@app.route('/login', methods=['POST'])
def showLogin():
    state = ''.join(
        random.choice(string.ascii_uppercase + string.digits) for x in range(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)

@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code, now compatible with Python3
    request.get_data()
    code = request.data.decode('utf-8')

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    # Submit request, parse response - Python3 compatible
    h = httplib2.Http()
    response = h.request(url, 'GET')[1]
    str_response = response.decode('utf-8')
    result = json.loads(str_response)

    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    return output

def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None

# DISCONNECT - Revoke a current user's token and reset their login_session

@app.route('/gdisconnect', methods=['POST'])
def gdisconnect():
        # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        # Reset the user's sesson.
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']

        # response = make_response(json.dumps('Successfully disconnected.'), 200)
        # response.headers['Content-Type'] = 'application/json'
        # return response
        return redirect(url_for('sportMenu'))
    else:
        # For whatever reason, the given token was invalid.
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response
@app.route('/catalog/JSON')
def sportsJSON():
    sports = session.query(Sports).all()
    return jsonify(Menu_Item=[i.serialize for i in sports])

@app.route('/catalog/<sport_name>/JSON')
def itemJSON(sport_name):
    sport = session.query(Sports).filter_by(name = sport_name).one()
    items = session.query(Essentials).filter_by(sport_id = sport.id).all()
    return jsonify(Item=[i.serialize for i in items])

@app.route('/')
@app.route('/main')
def sportMenu():
    menu = session.query(Sports).all()
    latest_items = session.query(Essentials).order_by(Essentials.id.desc()).limit(9).all()
    return render_template('main_menu.html', menu = menu,latest_items =latest_items,login_session =login_session)

@app.route('/catalog/<sport_name>/items')
def sportItem(sport_name):
    menu = session.query(Sports).all()
    sport_id = session.query(Sports).filter_by(name = sport_name).one()
    sport_item_list = session.query(Essentials).filter_by(sport_id =sport_id.id).all()
    items_count = session.query(Essentials).filter_by(sport_id =sport_id.id).count()
    return render_template('sport_items.html',menu = menu, sport_name = sport_name, sport_item_list=sport_item_list, items_count = items_count,login_session = login_session)

@app.route('/catalog/<sport_name>/<item_name>')
def itemDescription(sport_name,item_name):
    sport_id = session.query(Sports).filter_by(name = sport_name).one()
    item_id = session.query(Essentials).filter_by(name = item_name).one()
    sport_item_list = session.query(Essentials).filter_by(sport_id =sport_id.id, id = item_id.id).one()
    return render_template('description_page.html',item_name = item_name, sport_item_list = sport_item_list, login_session = login_session)

@app.route('/catalog/add_item', methods=['GET', 'POST'])
def addItem():
    if 'username' not in login_session:
        return redirect('/login')
    menu = session.query(Sports).all()
    if request.method == 'POST':
        newItem = Essentials(name=request.form['title'], description=request.form['description'],
                             sport_id=request.form['catg'], user_id=login_session['user_id'])
        session.add(newItem)
        session.commit()
        return redirect(url_for('sportMenu'))
    else:
        return render_template('add_item.html',menu = menu, login_session = login_session)

@app.route('/catalog/<item_name>/edit', methods=['GET', 'POST'])
def editItem(item_name):
    if 'username' not in login_session:
        return redirect('/login')
    menu = session.query(Sports).all()
    item = session.query(Essentials).filter_by(name = item_name).one()
    select_sport = session.query(Sports).filter_by(id = item.sport_id).one()
    if request.method == 'POST':
        updateItem = session.query(Essentials).filter_by(name = item_name,user_id=login_session['user_id']).one()
        if request.form['title']:
            updateItem.name = request.form['title']
        if request.form['description']:
            updateItem.description = request.form['description']
        if request.form['catg']:
            updateItem.sport_id = request.form['catg']
        session.add(updateItem)
        session.commit()
        return redirect(url_for('sportMenu'))
    else:
        return render_template('edit_item.html',menu = menu, login_session = login_session, item = item, select_sport = select_sport)

@app.route('/catalog/<item_name>/delete', methods=['GET', 'POST'])
def deleteItem(item_name):
    if 'username' not in login_session:
        return redirect('/login')
    itemToDelete = session.query(Essentials).filter_by(name = item_name).one()
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        return redirect(url_for('sportMenu'))
    else:
        return render_template('delete_item.html', login_session = login_session)

if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
