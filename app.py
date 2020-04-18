from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects.postgresql import BIGINT, JSONB, VARCHAR, INTEGER
from flask_marshmallow import Marshmallow
import uuid
import bcrypt
import jwt
import datetime
import time
from functools import wraps
import os
import requests
import json
from flask_cors import CORS, cross_origin
import sys  # Used to make log statements, add a line after log statement:
# sys.stdout.flush()

# remember to include uswgi, psycopg2, marshmallow-sqlalchemy in reqs.txt, also bcrypt==3.1.7 which pipreqs gets wrong:
# psycopg2_binary==2.8.3
# marshmallow-sqlalchemy==0.19.0
# bcrypt==3.1.7
# psycopg2==2.8.4
# uwsgi==2.0.18

app = Flask(__name__)
ma = Marshmallow(app)
CORS(app)


app.config['DEBUG'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['DATABASE_URL']
# app.config['SQLALCHEMY_DATABASE_URI'] = 'postgres:'
app.config['SECRET_KEY'] = 'totally%@#$%^T@#Secure!'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
# Pinata API endpoints
pinata_pin_list = 'https://api.pinata.cloud/data/pinList'
pinata_json_url = 'https://api.pinata.cloud/pinning/pinJSONToIPFS'


def log(string, item=None):
    print(string)
    if item is not None:
        print(json.dumps(item))
    sys.stdout.flush()

### Models ###


class Users(db.Model):
    __table_args__ = {'schema': 'admin'}
    user_id = db.Column(VARCHAR, primary_key=True)
    email = db.Column(VARCHAR)
    password_hash = db.Column(VARCHAR)
    pinata_api = db.Column(VARCHAR)
    pinata_key = db.Column(VARCHAR)

    def __init__(self, user_id, email, password_hash, pinata_api, pinata_key):
        self.user_id = user_id
        self.email = email
        self.password_hash = password_hash
        self.pinata_api = pinata_api
        self.pinata_key = pinata_key


class UserCollections(db.Model):
    user_id = db.Column(VARCHAR, primary_key=True)
    schedule = db.Column(JSONB)
    deck_ids = db.Column(JSONB)
    deleted_deck_ids = db.Column(JSONB)
    all_deck_cids = db.Column(JSONB)
    webapp_settings = db.Column(JSONB)
    extension_settings = db.Column(JSONB)
    highlight_urls = db.Column(JSONB)

    def __init__(self, user_id, schedule, deck_ids, deleted_deck_ids, all_deck_cids, webapp_settings, extension_settings, highlight_urls):
        self.user_id = user_id
        self.schedule = schedule
        self.deck_ids = deck_ids
        self.deleted_deck_ids = deleted_deck_ids
        self.all_deck_cids = all_deck_cids
        self.webapp_settings = webapp_settings
        self.extension_settings = extension_settings
        self.highlight_urls = highlight_urls


class Decks(db.Model):
    deck_id = db.Column(VARCHAR, primary_key=True)
    edited = db.Column(BIGINT)
    deck_cid = db.Column(VARCHAR)
    deck = db.Column(JSONB)
    title = db.Column(VARCHAR)
    card_count = db.Column(INTEGER)
    # created by?

    def __init__(self, deck_id, edited, deck_cid, deck, title, card_count):
        self.deck = deck
        # These values are repeated, should be the same as inside the deck, used for
        # Quick access of metadata, without an expensive query of the deck
        self.deck_id = deck_id
        self.edited = edited
        self.deck_cid = deck_cid
        self.title = title
        self.card_count = card_count


class Websites(db.Model):
    url = db.Column(VARCHAR, primary_key=True)
    site_owner = db.Column(VARCHAR)
    cards = db.Column(JSONB)
    lessons = db.Column(JSONB)
    highlights = db.Column(JSONB)
    deleted = db.Column(JSONB)

    def __init__(self, url, site_owner, cards, lessons, highlights, deleted):
        self.url = url
        self.site_owner = site_owner
        self.cards = cards
        self.lessons = lessons
        self.highlights = highlights
        self.deleted = deleted

### Schemas ###


class UserCollectionsSchema(ma.Schema):
    class Meta:
        fields = ("user_id", "schedule", "deck_ids", "all_deck_cids",
                  "deleted_deck_ids", "webapp_settings", "extension_settings", "highlight_urls")


class DecksSchema(ma.Schema):
    class Meta:
        fields = ("deck_id", "edited", "deck_cid",
                  "deck", "title", "card_count")


class WebsitesSchema(ma.Schema):
    class Meta:
        fields = ("url", "site_owner", "cards",
                  "lessons", "highlights", "deleted")


user_collection_schema = UserCollectionsSchema()
deck_schema = DecksSchema()
decks_schema = DecksSchema(many=True)
website_schema = WebsitesSchema()
websites_schema = WebsitesSchema(many=True)

### JWT token checker ###


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = Users.query.filter_by(
                user_id=data['user_id']).first()
        except:
            return jsonify({'message': 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated


### API call routes ###

@app.route('/sign_up', methods=['POST'])
@cross_origin(origin='*')
def sign_up():
    data = request.get_json()
    exists = Users.query.filter_by(email=data['email']).first()
    if exists is not None:
        return jsonify({"error": "Email already exists"})
    else:
        hashed_password = bcrypt.hashpw(
            data['password'].encode('utf8'), bcrypt.gensalt())
        user_id = str(uuid.uuid4())
        new_user = Users(user_id=user_id,
                         email=data['email'],
                         password_hash=hashed_password.decode('utf8'),
                         pinata_api=data['pinata_api'],
                         pinata_key=data['pinata_key'])
        db.session.add(new_user)

        new_collection = UserCollections(user_id=user_id,
                                         schedule={},
                                         deck_ids=[],
                                         deleted_deck_ids=[],
                                         all_deck_cids=[],
                                         webapp_settings={},
                                         extension_settings={},
                                         highlight_urls={
                                             'list': [], 'edited': 0}
                                         )
        if 'user_collection' in data:
            new_collection.schedule = data['user_collection']['schedule']
            new_collection.deleted_deck_ids = data['user_collection']['deleted_deck_ids']
            new_collection.all_deck_cids = data['user_collection']['all_deck_cids']
            new_collection.webapp_settings = data['user_collection']['webapp_settings']
            new_collection.extension_settings = data['user_collection']['extension_settings']
            new_collection.highlight_urls = data['user_collection']['highlight_urls']
        db.session.add(new_collection)
        db.session.commit()
        return jsonify({'message': 'New user created!'})


@app.route('/login',  methods=['GET'])
# @cross_origin(origin='*')
def login():
    # log("    starting login ", str(datetime.datetime.utcnow()))
    sys.stdout.flush()
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return jsonify({"error": "Invalid credentials"})

    user = Users.query.filter_by(email=auth.username).first()
    if not user:
        return jsonify({"error": "Invalid credentials"})

    # verified path
    if bcrypt.checkpw(auth.password.encode('utf8'), user.password_hash.encode('utf8')):
        token = jwt.encode({'user_id': user.user_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(days=3)},
                           app.config['SECRET_KEY'])

        # Get pinata keys
        log("    Getting pinata keys " + str(datetime.datetime.utcnow()))
        sys.stdout.flush()
        user = Users.query.filter_by(user_id=user.user_id).first()
        pinata_keys = {'pinata_api': user.pinata_api,
                       'pinata_key': user.pinata_key, }

        # # Get decks metadata
        # log("    Getting decks meta " + str(datetime.datetime.utcnow()))
        # sys.stdout.flush()
        # deck_ids = user_collection.deck_ids
        # decks_meta = []
        # for deck_id in deck_ids:
        #     deck = Decks.query.filter_by(deck_id=deck_id).first()
        #     dump = deck_schema.dump(deck)
        #     if len(dump) > 3:
        #         deck_meta = {
        #             'title': dump['title'],
        #             'edited': dump['edited'],
        #             'deck_cid': dump['deck_cid'],
        #             'deck_id': dump['deck_id']
        #         }
        #         decks_meta.append(deck_meta)
        #     # delete blank or incomplete decks
        #     else:
        #         log("    incomplete decks detected ", dump)
        #         sys.stdout.flush()
        #         db.session.query(Decks).filter(Decks.deck_id == deck_id).delete()
        #         if deck_id in user_collection.deck_ids:
        #             deck_ids_list = user_collection.deck_ids.copy()
        #             deck_ids_list.remove(deck_id)
        #             user_collection.deck_ids = deck_ids_list
        #         if deck_id not in user_collection.deleted_deck_ids:
        #             deleted_deck_ids_list = user_collection.deleted_deck_ids.copy()
        #             deleted_deck_ids_list.append(deck_id)
        #             user_collection.deleted_deck_ids = deleted_deck_ids_list
        #         db.session.commit()

        login_return_data = {
            'token': token.decode('UTF-8'),
            'pinata_keys': pinata_keys,
            'user_id': user.user_id,
        }
        log("    returning" + str(datetime.datetime.utcnow()))
        sys.stdout.flush()
        return jsonify(login_return_data)

    return jsonify({"error": "Invalid credentials"})


# deprecated -already added this step to sign up. leaving this just in case
@app.route('/post_user_collection', methods=['POST'])
@cross_origin(origin='*')
@token_required
def post_user_collection(current_user):
    data = request.get_json()

    new_collection = UserCollections(user_id=current_user.user_id,
                                     schedule=data['schedule'],
                                     deck_ids=data['deck_ids'],
                                     deleted_deck_ids=data['deleted_deck_ids'],
                                     all_deck_cids=data['all_deck_cids'],
                                     webapp_settings=data['webapp_settings'],
                                     extension_settings=data['extension_settings'],
                                     highlight_urls=data['highlight_urls'],
                                     )
    db.session.add(new_collection)
    db.session.commit()

    return user_collection_schema.dump(new_collection)


@app.route('/get_decks_meta_and_collection', methods=['GET'])
@cross_origin(origin='*')
@token_required
def get_decks_meta_and_collection(current_user):

    # check pinata here
    user_collection = user_collection_schema.dump(UserCollections.query.filter_by(
        user_id=current_user.user_id).first())
    deck_ids = user_collection['deck_ids']
    return_data = {
        'user_collection': user_collection,
        'decks_meta': []
    }
    for deck_id in deck_ids:
        # getting the whole schema includes the deck. Should update this to only get the meta feilds
        dump = deck_schema.dump(Decks.query.filter_by(deck_id=deck_id).first())
        if len(dump) > 3:   # this shouldnt be the case, maybe do a check on login that deck colleciton and decks are aligned or empty
            deck_meta = {
                'title': dump['title'],
                'edited': dump['edited'],
                'deck_cid': dump['deck_cid'],
                'deck_id': dump['deck_id'],
                'card_count': dump['card_count']
            }
            return_data['decks_meta'].append(deck_meta)

    return jsonify(return_data)


@app.route('/get_user_collection', methods=['GET'])
@cross_origin(origin='*')
@token_required
def get_user_collection(current_user):
    # check pinata here
    user_collection = UserCollections.query.filter_by(
        user_id=current_user.user_id).first()
    return user_collection_schema.dump(user_collection)


@app.route('/put_user_collection', methods=['PUT'])
@cross_origin(origin='*')
@token_required
def put_user_collection(current_user):
    data = request.get_json()
    user_collection = UserCollections.query.filter_by(
        user_id=current_user.user_id).first()
    if 'schedule' in data:
        user_collection.schedule = data['schedule']
    if 'deck_ids' in data:
        user_collection.deck_ids = data['deck_ids']
    if 'deleted_deck_ids' in data:
        user_collection.deleted_deck_ids = data['deleted_deck_ids']
    if 'all_deck_cids' in data:
        user_collection.all_deck_cids = data['all_deck_cids']
    if 'webapp_settings' in data:
        user_collection.webapp_settings = data['webapp_settings']
    if 'extension_settings' in data:
        user_collection.extension_settings = data['extension_settings']
    if 'highlight_urls' in data:
        log('update highlight_urls', data)
        user_collection.highlight_urls = data['highlight_urls']

    db.session.commit()
    user_collection = UserCollections.query.filter_by(
        user_id=current_user.user_id).first()
    return user_collection_schema.dump(user_collection)


@app.route('/get_deck', methods=['POST'])
@cross_origin(origin='*')
@token_required
def get_deck(current_user):
    data = request.get_json()
    deck_id = data['deck_id']
    dump = deck_schema.dump(Decks.query.filter_by(deck_id=deck_id).first())
    return dump['deck']


@app.route('/get_decks', methods=['POST'])
@cross_origin(origin='*')
@token_required
def get_decks(current_user):
    data = request.get_json()
    deck_ids = data
    decks = []
    for deck_id in deck_ids:
        dump = deck_schema.dump(Decks.query.filter_by(deck_id=deck_id).first())
        if 'deck' in dump:
            decks.append(dump['deck'])
    return jsonify(decks)


@app.route('/post_deck', methods=['POST'])
@cross_origin(origin='*')
@token_required
def post_deck(current_user):
    client_deck = request.get_json()
    exists_in_decks = Decks.query.filter_by(
        deck_id=client_deck['deck_id']).first()
    user_collection = UserCollections.query.filter_by(
        user_id=current_user.user_id).first()
    if client_deck['deck_id'] not in user_collection.deck_ids:
        deck_ids_list = user_collection.deck_ids.copy()
        deck_ids_list.append(client_deck['deck_id'])
        user_collection.deck_ids = deck_ids_list
        db.session.commit()
    pinata_api = current_user.pinata_api
    pinata_key = current_user.pinata_key
    pinata_api_headers = {"Content-Type": "application/json", "pinata_api_key": pinata_api,
                          "pinata_secret_api_key": pinata_key}

    if exists_in_decks is not None:
        return jsonify({"error": "Deck already exists"})
    else:
        new_deck = Decks(
            deck=client_deck,
            # these echo 'deck' internal info to allow for less expensive database metadata queries
            deck_id=client_deck['deck_id'],
            title=client_deck['title'],
            edited=client_deck['edited'],
            deck_cid="",
            card_count=len(client_deck['cards'])
        )
        db.session.add(new_deck)
        db.session.commit()
        json_data_for_API = {}
        json_data_for_API["pinataMetadata"] = {
            "name": new_deck.title,
            "keyvalues": {"deck_id": new_deck.deck_id, "edited": new_deck.edited}
        }
        json_data_for_API["pinataContent"] = deck_schema.dump(new_deck)
        req = requests.post(
            pinata_json_url, json=json_data_for_API, headers=pinata_api_headers)
        pinata_api_response = json.loads(req.text)
        log("    uploaded deck to IPFS. Hash: " +
            pinata_api_response["IpfsHash"])
        sys.stdout.flush()
        deck_cid = pinata_api_response["IpfsHash"]
        new_deck.deck_cid = deck_cid
        db.session.commit()
        return deck_schema.dump(new_deck)


@app.route('/post_decks', methods=['POST'])
@cross_origin(origin='*')
@token_required
def post_decks(current_user):
    client_decks = request.get_json()
    decks_added = []
    decks_not_added = []
    user_collection = UserCollections.query.filter_by(
        user_id=current_user.user_id).first()
    for client_deck in client_decks:
        if client_deck['deck_id'] not in user_collection.deck_ids:
            # aparently you can't directly append a list in SQLalchemy
            deck_ids_list = user_collection.deck_ids.copy()
            deck_ids_list.append(client_deck['deck_id'])
            user_collection.deck_ids = deck_ids_list
            db.session.commit()
        exists = Decks.query.filter_by(deck_id=client_deck['deck_id']).first()
        pinata_api = current_user.pinata_api
        pinata_key = current_user.pinata_key
        pinata_api_headers = {"Content-Type": "application/json", "pinata_api_key": pinata_api,
                              "pinata_secret_api_key": pinata_key}
        if exists is not None:
            decks_not_added.append(client_deck['title'])
        else:
            new_deck = Decks(
                deck=client_deck,
                # these echo 'deck' internal info to allow for less expensive database metadata queries
                deck_id=client_deck['deck_id'],
                title=client_deck['title'],
                edited=client_deck['edited'],
                deck_cid="",
                card_count=len(client_deck['cards'])
            )
            db.session.add(new_deck)
            db.session.commit()
            json_data_for_API = {}
            json_data_for_API["pinataMetadata"] = {
                "name": new_deck.title,
                "keyvalues": {"deck_id": new_deck.deck_id, "edited": new_deck.edited}
            }
            json_data_for_API["pinataContent"] = deck_schema.dump(new_deck)
            req = requests.post(
                pinata_json_url, json=json_data_for_API, headers=pinata_api_headers)
            pinata_api_response = json.loads(req.text)
            log("    uploaded deck to IPFS. Hash: " +
                pinata_api_response["IpfsHash"])
            sys.stdout.flush()
            deck_cid = pinata_api_response["IpfsHash"]
            new_deck.deck_cid = deck_cid
            db.session.commit()
            decks_added.append(client_deck['title'])

    return jsonify({'decks_added': decks_added, 'decks_not_added': decks_not_added})


@app.route('/put_deck', methods=['PUT'])
@cross_origin(origin='*')
@token_required
def put_deck(current_user):
    client_deck = request.get_json()
    server_deck = Decks.query.filter_by(
        deck_id=client_deck['deck_id']).first()
    pinata_api = current_user.pinata_api
    pinata_key = current_user.pinata_key
    pinata_api_headers = {"Content-Type": "application/json", "pinata_api_key": pinata_api,
                          "pinata_secret_api_key": pinata_key}
    # Check IPFS metadata here-------
    # query_string = '?metadata[keyvalues]={"deck_id":{"value":"' + data['deck_id'] + '","op":"eq"}}'
    # req = requests.get(pinata_pin_list + query_string, headers=pinata_api_headers)
    # pinata_data = json.loads(req.text)
    # if pinata_data['edited'] > server_deck.edited and pinata_data['edited'] > data['edited']:
    # server_deck... = pinata_data['...']
    # db.session.commit()

    # this check should've already been performed in app, but its not too expensive
    # check edited date isn't older than one in database, if it is, return newest
    # and data['edited'] > pinata_data['edited']:
    if client_deck['edited'] > server_deck.edited:
        server_deck.deck = client_deck
        server_deck.title = client_deck['title']
        server_deck.edited = client_deck['edited']
        server_deck.card_count = len(client_deck['cards'])
        db.session.commit()

        # then if the pinata version wasn't the newest, upload to pinata

        # change this when add pinata

        # if pinata_data['edited'] < server_deck.edited or pinata_data['edited'] < data['edited']:
        json_data_for_API = {}
        json_data_for_API["pinataMetadata"] = {
            "name": server_deck.title,
            "keyvalues": {"deck_id": server_deck.deck_id, "edited": server_deck.edited}
        }
        json_data_for_API["pinataContent"] = deck_schema.dump(server_deck)
        req = requests.post(
            pinata_json_url, json=json_data_for_API, headers=pinata_api_headers)
        pinata_api_response = json.loads(req.text)
        log("    uploaded deck to IPFS. Hash: " +
            pinata_api_response["IpfsHash"])
        sys.stdout.flush()
        server_deck.deck_cid = pinata_api_response["IpfsHash"]
        db.session.commit()
        return jsonify({'message': 'Deck updated', 'deck': deck_schema.dump(server_deck)})

    # else return the database version saved as server_deck
    else:  # do we need the dump? compare with put_decks
        return jsonify({'message': 'Server decks is newer', 'deck': deck_schema.dump(server_deck)})


@app.route('/put_decks', methods=['PUT'])
@cross_origin(origin='*')
@token_required
def put_decks(current_user):
    pinata_api = current_user.pinata_api
    pinata_key = current_user.pinata_key
    pinata_api_headers = {"Content-Type": "application/json", "pinata_api_key": pinata_api,
                          "pinata_secret_api_key": pinata_key}
    updated_decks = []
    not_updated_decks = []
    data = request.get_json()
    for client_deck in data:
        server_deck = Decks.query.filter_by(
            deck_id=client_deck['deck_id']).first()

        # Check IPFS metadata here-------
        # query_string = '?metadata[keyvalues]={"deck_id":{"value":"' + data['deck_id'] + '","op":"eq"}}'
        # req = requests.get(pinata_pin_list + query_string, headers=pinata_api_headers)
        # pinata_data = json.loads(req.text)
        # if pinata_data['edited'] > server_deck.edited and pinata_data['edited'] > data['edited']:
        # server_deck... = pinata_data['...']
        # db.session.commit()

        # this check should've already been performed in app, but its not too expensive
        # check edited date isn't older than one in database, if it is, return newest
        # and data['edited'] > pinata_data['edited']:
        if client_deck['edited'] > server_deck.edited:
            # https:    //stackoverflow.com/questions/47735329/updating-a-row-using-sqlalchemy-orm
            # some weirdness where there is no .update function unless you use .query
            db.session.query(Decks).filter(Decks.deck_id == client_deck['deck_id']).update({
                'deck': client_deck,
                'title': client_deck['title'],
                'edited': client_deck['edited'],
                'card_count': len(client_deck['cards'])
            }, synchronize_session=False)

            db.session.commit()

            # then if the pinata version wasn't the newest, upload to pinata

            # change this when add pinata

            # if pinata_data['edited'] < server_deck.edited or pinata_data['edited'] < data['edited']:
            json_data_for_API = {}
            json_data_for_API["pinataMetadata"] = {
                "name": server_deck.title,
                "keyvalues": {"deck_id": server_deck.deck_id, "edited": server_deck.edited}
            }
            json_data_for_API["pinataContent"] = deck_schema.dump(server_deck)
            req = requests.post(
                pinata_json_url, json=json_data_for_API, headers=pinata_api_headers)
            pinata_api_response = json.loads(req.text)
            log("    uploaded deck to IPFS. Hash: " +
                pinata_api_response["IpfsHash"])
            sys.stdout.flush()
            server_deck.deck_cid = pinata_api_response["IpfsHash"]
            db.session.commit()
            updated_decks.append(server_deck.deck_id)
        # else return the database version saved as server_deck
        else:
            not_updated_decks.append(server_deck.deck_id)

    return jsonify({"updated decks": updated_decks, "not updated decks": not_updated_decks})


@app.route('/delete_deck', methods=['DELETE'])
@cross_origin(origin='*')
@token_required
def delete_deck(current_user):
    data = request.get_json()
    deck_id = data['deck_id']
    deck = Decks.query.filter_by(deck_id=deck_id).first()

    if not deck:
        return jsonify({'message': 'No deck found!'})

    db.session.delete(deck)
    user_collection = UserCollections.query.filter_by(
        user_id=current_user.user_id).first()
    if deck_id in user_collection.deck_ids:
        deck_ids_list = user_collection.deck_ids.copy()
        deck_ids_list.remove(deck_id)
        user_collection.deck_ids = deck_ids_list
    if deck_id not in user_collection.deleted_deck_ids:
        deleted_deck_ids_list = user_collection.deleted_deck_ids.copy()
        deleted_deck_ids_list.append(deck_id)
        user_collection.deleted_deck_ids = deleted_deck_ids_list
    db.session.commit()
    return jsonify({'message': 'Deck deleted!'})


@app.route('/delete_decks', methods=['DELETE'])
@cross_origin(origin='*')
@token_required
def delete_decks(current_user):
    reply_message = {'message': ''}
    user_collection = UserCollections.query.filter_by(
        user_id=current_user.user_id).first()
    data = request.get_json()
    for deck_id in data['deck_ids']:
        deck = Decks.query.filter_by(deck_id=deck_id).first()
        if not deck:
            reply_message['message'] += '    No deck found!: ' + deck_id
        else:
            db.session.delete(deck)
            reply_message['message'] += '    Deck Deleted!: ' + deck_id
        if deck_id in user_collection.deck_ids:
            deck_ids_list = user_collection.deck_ids.copy()
            deck_ids_list.remove(deck_id)
            user_collection.deck_ids = deck_ids_list
        if deck_id not in user_collection.deleted_deck_ids:
            deleted_deck_ids_list = user_collection.deleted_deck_ids.copy()
            deleted_deck_ids_list.append(deck_id)
            user_collection.deleted_deck_ids = deleted_deck_ids_list
    db.session.commit()
    return jsonify(reply_message)


@app.route('/post_card', methods=['POST'])
@cross_origin(origin='*')
@token_required
def post_card(current_user):
    data = request.get_json()
    card = data['card']
    deck_id = data['deck_id']
    server_deck = Decks.query.filter_by(deck_id=deck_id).first()
    deck_dump = deck_schema.dump(server_deck)
    deck = deck_dump['deck']
    log('deck', deck)
    deck['cards'].append(card)
    log('cards after', deck['cards'])
    now = time.time() * 1000
    log('edited before', deck['edited'])
    deck['edited'] = now
    log('edited after', deck['edited'])

    deck['card_count'] = len(deck['cards'])

    db.session.query(Decks).filter(Decks.deck_id == deck_id).update({
        'deck': deck,
        'edited': now,
        'card_count': len(deck['cards'])
    }, synchronize_session=False)
    db.session.commit()
    server_deck = deck_schema.dump(
        Decks.query.filter_by(deck_id=deck_id).first())
    log('server deck after', server_deck)
    return jsonify({'added card': card})


@app.route('/put_card', methods=['PUT'])
@cross_origin(origin='*')
@token_required
def put_card(current_user):
    data = request.get_json()
    card = data['card']
    deck_id = data['deck_id']
    server_deck = Decks.query.filter_by(deck_id=deck_id).first()
    deck_dump = deck_schema.dump(server_deck)
    deck = deck_dump['deck']
    log('cards before', deck['cards'])
    for index in range(0, len(deck['cards'])):
        if deck['cards'][index]['card_id'] == card['card_id']:
            log('card before', deck['cards'][index])
            deck['cards'][index] = card
            log('card after', deck['cards'][index])
            log('cards after', deck['cards'])

            now = time.time() * 1000
            deck['edited'] = now
            deck['card_count'] = len(deck['cards'])

            db.session.query(Decks).filter(Decks.deck_id == deck_id).update({
                'deck': deck,
                'edited': now,
                'card_count': len(deck['cards'])
            }, synchronize_session=False)
            db.session.commit()
            server_deck = deck_schema.dump(
                Decks.query.filter_by(deck_id=deck_id).first())
            log('server deck after', server_deck)
            return jsonify({'updated card': card})
    return jsonify({'message': 'card not found'})


@app.route('/get_deck_meta', methods=['POST'])
@cross_origin(origin='*')
@token_required
def get_deck_meta(current_user):
    data = request.get_json()
    deck_id = data['deck_id']
    dump = deck_schema.dump(Decks.query.filter_by(deck_id=deck_id).first())
    if dump is not None:
        deck_meta = {
            'title': dump['title'],
            'edited': dump['edited'],
            'deck_cid': dump['deck_cid'],
            'deck_id': dump['deck_id'],
            'card_count': dump['card_count']
        }
    return jsonify(deck_meta)


@app.route('/get_decks_meta', methods=['GET'])
@cross_origin(origin='*')
@token_required
def get_decks_meta(current_user):
    user_collection = UserCollections.query.filter_by(
        user_id=current_user.user_id).first()
    deck_ids = user_collection.deck_ids
    decks_meta = []
    for deck_id in deck_ids:
        dump = deck_schema.dump(Decks.query.filter_by(deck_id=deck_id).first())
        if len(dump) > 3:   # this shouldnt be the case, maybe do a check on login that deck colleciton and decks are aligned or empty
            deck_meta = {
                'title': dump['title'],
                'edited': dump['edited'],
                'deck_cid': dump['deck_cid'],
                'deck_id': dump['deck_id'],
                'card_count': dump['card_count']
            }
            decks_meta.append(deck_meta)
    return jsonify(decks_meta)


@app.route('/get_websites_meta', methods=['GET'])
@cross_origin(origin='*')
@token_required
def get_websites_meta(current_user):
    # issue is that its returning deleted cards
    log('   >>>>>>> get_websites_meta')
    user_collection = user_collection_schema.dump(
        UserCollections.query.filter_by(user_id=current_user.user_id).first())
    # we want to structure this like the 'highlights' object in the extension
    websites_meta = {}
    # log('highlight_urls', user_collection['highlight_urls'])
    for url in user_collection['highlight_urls']['list']:
        website = website_schema.dump(
            Websites.query.filter_by(url=url).first())
        if website is None or website == {}:
            log('website not found', url)
            websites_meta[url] = 'website not found'
        else:
            # log('website', website)
            websites_meta[url] = {}
            if 'cards' in website:
                websites_meta[url]['cards'] = []
                for card in website['cards']:
                    websites_meta[url]['cards'].append(
                        {'card_id': card['card_id'], 'edited': card['edited'], 'user_id': card['user_id']})
            if 'deleted' in website:
                websites_meta[url]['deleted'] = website['deleted']
            if 'highlights' in website:
                websites_meta[url]['highlights'] = {}
                for highlight in website['highlights']:
                    websites_meta[url]['highlights'][highlight] = {
                        'edited':  website['highlights'][highlight]['edited'],
                        'user_id':  website['highlights'][highlight]['user_id']
                    }
    return jsonify({'websites_meta': websites_meta})


@app.route('/get_websites_selected_content', methods=['POST'])
@cross_origin(origin='*')
@token_required
def get_websites_selected_content(current_user):
    # also returning deleted cards
    log('>>>>>> get_websites_selected_content')
    data = request.get_json()
    results = {}
    for url in data:
        server_website = website_schema.dump(
            Websites.query.filter_by(url=url).first())
        # log('server_website', server_website)
        if server_website is not None and server_website != {}:
            results[url] = {}
            client_website = data[url]
            if 'deleted' in server_website and 'deleted' in client_website:
                results[url]['deleted'] = []
                for item in server_website['deleted']:
                    if item in client_website['deleted']:
                        results[url]['deleted'].append(item)
            if 'highlights' in server_website and 'highlights' in client_website:
                results[url]['highlights'] = {}
                for highlight_id in server_website['highlights']:
                    for highlight_id_c in client_website['highlights']:
                        if highlight_id == highlight_id_c:
                            results[url]['highlights'][highlight_id] = server_website['highlights'][highlight_id]
                            break
            if 'cards' in server_website and 'cards' in client_website:
                results[url]['cards'] = []
                for card in server_website['cards']:
                    for card_c in client_website['cards']:
                        if card['card_id'] == card_c['card_id']:
                            results[url]['cards'].append(card)
                            break

    return jsonify({'websites': results})

# can use this for POST and PUT
@app.route('/post_websites', methods=['POST'])
@cross_origin(origin='*')
@token_required
def post_websites(current_user):
    """Can use this for POST and PUT of highlights.
    Make sure to sync user_collection so that our highlights_url is up to date, and compare_highlights first"""
    log('    >>>>>> post_websites')
    return_message = {}

    def create_new_website(client_website):
        highlights = {}
        # log('client_website', client_website)
        if 'highlights' in client_website:
            for highlight in client_website['highlights']:
                if client_website['highlights'][highlight]['user_id'] == user_id:
                    highlights[highlight] = client_website['highlights'][highlight]
        cards = []
        if 'cards' in client_website:
            for card in client_website['cards']:
                if card['user_id'] == user_id:
                    cards.append(card)
        deleted = []
        if 'deleted' in client_website:
            deleted = client_website['deleted']

        new_url = Websites(url=url, highlights=highlights,
                           cards=cards, site_owner='', lessons={}, deleted=deleted)
        # log('added url', {'highlights': highlights, 'cards': cards})
        db.session.add(new_url)
        db.session.commit()
        if 'websites added' not in return_message:
            return_message['websites added'] = {}
        return_message['websites added'][url] = {
            'highlights': highlights, 'cards': cards, 'deleted': deleted}

    data = request.get_json()
    # log('  data', data)
    user_collection = UserCollections.query.filter_by(
        user_id=current_user.user_id).first()
    user_id = user_collection.user_id
    client_websites = data['websites']
    for url in client_websites:
        client_website = client_websites[url]
        # log('client_website', client_website)
        server_website = website_schema.dump(
            Websites.query.filter_by(url=url).first())
        # log('server_website', server_website)
        # log('client_website', client_website)
        if server_website is None:
            create_new_website(client_website)
        elif server_website == {}:
            create_new_website(client_website)
        else:
            highlights = {}
            cards = []
            deleted = []
            if 'deleted' in client_website:
                deleted = client_website['deleted']
            elif 'deleted' in server_website:
                deleted = server_website['deleted']

            if 'highlights' in server_website:
                for highlight in server_website['highlights']:
                    if highlight not in deleted:
                        highlights[highlight] = server_website['highlights'][highlight]
            if 'highlights' in client_website:
                for highlight in client_website['highlights']:
                    if highlight not in deleted:
                        if client_website['highlights'][highlight]['user_id'] == user_id:
                            highlights[highlight] = client_website['highlights'][highlight]
            client_card_ids = []
            if 'cards' in client_website:
                for card in client_website['cards']:
                    if card['card_id'] not in deleted:
                        cards.append(card)
                        client_card_ids.append(card['card_id'])
            if 'cards' in server_website:
                for card in server_website['cards']:
                    if card['card_id'] not in deleted and card['card_id'] not in client_card_ids:
                        cards.append(card)

            update_info = {'highlights': highlights,
                           'cards': cards,
                           'deleted': deleted}
            # log('updated entry: url, - ' + url + '  ', update_info)
            db.session.query(Websites).filter(Websites.url == url).update(
                {'highlights': highlights,
                 'cards': cards,
                 'deleted': deleted}, synchronize_session=False)
            db.session.commit()
            if 'websites updated' not in return_message:
                return_message['websites updated'] = {}
            return_message['websites updated'][url] = {
                'highlights': highlights, 'cards': cards, 'deleted': deleted}

    return jsonify(return_message)


# get_website_highlights_and_cards

# get_website_cards

# get website_all
@app.route('/get_website', methods=['POST'])
@cross_origin(origin='*')
@token_required
def get_website(current_user):
    # also returning deleted cards
    log('>>>>>> get_website')
    data = request.get_json()
    url = data['url']
    # log('data', data)
    server_website = website_schema.dump(
        Websites.query.filter_by(url=url).first())
    # log('server_website', server_website)
    website = {}
    if server_website is not None and server_website != {}:
        website = server_website
    return jsonify({'website': website})

# get website_mine

# get websites_mine_all

# put website_all

# put website_mine

# put websites_mine_all

# post website

# add_highlight


if __name__ == '__main__':
    app.run(debug=True)
