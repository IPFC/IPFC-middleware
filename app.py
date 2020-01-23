from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects.postgresql import BIGINT, JSONB, VARCHAR
from flask_marshmallow import Marshmallow
import uuid
import bcrypt
import jwt
import datetime
from functools import wraps
import os
import requests
import json
from flask_cors import CORS, cross_origin
import sys # Used to make print statements, add a line after print statement:
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
app.config['SECRET_KEY'] = 'totally%@#$%^T@#Secure!'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

pinata_pin_list = 'https://api.pinata.cloud/data/pinList'
pinata_json_url = 'https://api.pinata.cloud/pinning/pinJSONToIPFS'

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
    sr_id = db.Column(VARCHAR)
    deck_ids = db.Column(JSONB)
    all_deck_cids = db.Column(JSONB)

    def __init__(self, user_id, sr_id, deck_ids, all_deck_cids):
        self.user_id = user_id
        self.sr_id = sr_id
        self.deck_ids = deck_ids
        self.all_deck_cids = all_deck_cids


class Decks(db.Model):
    deck_id = db.Column(VARCHAR, primary_key=True)
    edited = db.Column(BIGINT)
    deck_cid = db.Column(VARCHAR)
    deck = db.Column(JSONB)
    title = db.Column(VARCHAR)
    # created by?

    def __init__(self, deck_id, edited, deck_cid, deck, title):
        self.deck = deck
        # These values are repeated, should be the same as inside the deck, used for 
        # Quick access of metadata, without an expensive query of the deck
        self.deck_id = deck_id
        self.edited = edited
        self.deck_cid = deck_cid
        self.title = title
        


### Schemas ###

class UserCollectionsSchema(ma.Schema):
    class Meta:
        fields = ("user_id", "sr_id", "deck_ids", "all_deck_cids")


class DecksSchema(ma.Schema):
    class Meta:
        fields = ("deck_id", "edited", "deck_cid", "deck", "title")


user_collection_schema = UserCollectionsSchema()
deck_schema = DecksSchema()
decks_schema = DecksSchema(many=True)


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
            current_user = Users.query.filter_by(user_id=data['user_id']).first()
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
        hashed_password = bcrypt.hashpw(data['password'].encode('utf8'), bcrypt.gensalt())
        user_id = str(uuid.uuid4())
        new_user = Users(user_id=user_id,
                         email=data['email'],
                         password_hash=hashed_password.decode('utf8'),
                         pinata_api=data['pinata_api'],
                         pinata_key=data['pinata_key'])
        db.session.add(new_user)

        new_collection = UserCollections(user_id=user_id,
                                         sr_id=str(uuid.uuid4()),
                                         all_deck_cids=[],
                                         deck_ids=[],)
        db.session.add(new_collection)
        db.session.commit()
        return jsonify({'message': 'New user created!'})


@app.route('/login')
@cross_origin(origin='*')
def login():
    print("starting login" + str(datetime.datetime.utcnow()))
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
        # Get user collection
        print("Getting user collection" + str(datetime.datetime.utcnow()))
        sys.stdout.flush()
        user_collection = UserCollections.query.filter_by(user_id=user.user_id).first()

        # Get decks metadata
        print("Getting decks meta" + str(datetime.datetime.utcnow()))
        sys.stdout.flush()
        deck_ids = user_collection.deck_ids
        decks_meta = []
        for deck_id in deck_ids:
            dump = deck_schema.dump(Decks.query.filter_by(deck_id=deck_id).first())
            deck_meta = {
                'title': dump['title'],
                'edited': dump['edited'],
                'deck_cid': dump['deck_cid'],
                'deck_id': dump['deck_id']
            }
            decks_meta.append(deck_meta)

        decks = []
        print("Getting decks" + str(datetime.datetime.utcnow()))
        sys.stdout.flush()
        # Preload up to 10 decks here..... just get them all, up to 100? do speed tests to decide
        # Realized we can't create the review deck without all the decks. 
        # need to optimize this later, if data is large....
        # if len(deck_ids) <= 10:
        for deck_id in deck_ids:
            dump = deck_schema.dump(Decks.query.filter_by(deck_id=deck_id).first())
            decks.append(dump['deck'])
        # else:
        #     deck_ids.sort(reverse=True)
        #     for i in range(10):
        #         dump = deck_schema.dump(Decks.query.filter_by(deck_id=deck_ids[i]).first())
        #         decks.append(dump['deck'])

        login_return_data = {'user_collection': user_collection_schema.dump(user_collection),
                             'token': token.decode('UTF-8'),
                             'decks_meta': decks_meta,
                             'decks': decks}
        print("returning" + str(datetime.datetime.utcnow()))
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
                                     sr_id=str(uuid.uuid4()),
                                     all_deck_cids=data['all_deck_cids'],
                                     deck_ids=data['deck_ids'])
    db.session.add(new_collection)
    db.session.commit()

    return user_collection_schema.dump(new_collection)


@app.route('/get_user_collection', methods=['GET'])
@cross_origin(origin='*')
@token_required
def get_user_collection(current_user):

    user_collection = UserCollections.query.filter_by(user_id=current_user.user_id).first()
    return user_collection_schema.dump(user_collection)


@app.route('/put_user_collection', methods=['PUT'])
@cross_origin(origin='*')
@token_required
def put_user_collection(current_user):
    data = request.get_json()
    user_collection = UserCollections.query.filter_by(user_id=current_user.user_id).first()
    if 'sr_id' in data:
        user_collection.sr_id = data['sr_id']
    if 'deck_ids' in data:
        user_collection.deck_ids = data['deck_ids']
    if 'all_deck_cids' in data:
        user_collection.all_deck_cids = data['all_deck_cids']

    db.session.commit()
    return user_collection_schema.dump(user_collection)


@app.route('/get_deck', methods=['GET'])
@cross_origin(origin='*')
@token_required
def get_deck(current_user):
    data = request.get_json()
    deck_id = data['deck_id']
    dump = deck_schema.dump(Decks.query.filter_by(deck_id=deck_id).first())
    return dump['deck']


@app.route('/get_decks', methods=['GET'])
@cross_origin(origin='*')
@token_required
def get_decks(current_user):
    data = request.get_json()
    deck_ids = data['deck_ids']
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
    data = request.get_json()
    exists = Decks.query.filter_by(deck_id=data['deck_id']).first()
    pinata_api = current_user.pinata_api
    pinata_key = current_user.pinata_key
    pinata_api_headers = {"Content-Type": "application/json", "pinata_api_key": pinata_api,
                          "pinata_secret_api_key": pinata_key}
    if exists is not None:
        return jsonify({"error": "Deck already exists"})
    else:
        new_deck = Decks(
            deck=data['deck'],
            # these echo 'deck' internal info to allow for less expensive database metadata queries
            deck_id=data['deck_id'],
            title=data['title'],
            edited=data['edited'],
            deck_cid=""
            )
        json_data_for_API = {}
        json_data_for_API["pinataMetadata"] = {
            "name": new_deck.title,
            "keyvalues": {"deck_id": new_deck.deck_id, "edited": new_deck.edited}
            }
        json_data_for_API["pinataContent"] = deck_schema.dump(new_deck)
        req = requests.post(pinata_json_url, json=json_data_for_API, headers=pinata_api_headers)
        pinata_api_response = json.loads(req.text)
        print("uploaded deck to IPFS. Hash: " + pinata_api_response["IpfsHash"])
        sys.stdout.flush()
        deck_cid = pinata_api_response["IpfsHash"]
        new_deck.deck_cid = deck_cid
        db.session.add(new_deck)
        db.session.commit()
        return deck_schema.dump(new_deck)


@app.route('/put_deck', methods=['PUT'])
@cross_origin(origin='*')
@token_required
def put_deck(current_user):
    data = request.get_json()
    deck_id = data['deck_id']
    deck_to_update = Decks.query.filter_by(deck_id=deck_id).first()
    pinata_api = current_user.pinata_api
    pinata_key = current_user.pinata_key
    pinata_api_headers = {"Content-Type": "application/json", "pinata_api_key": pinata_api,
                          "pinata_secret_api_key": pinata_key}
    # Check IPFS metadata here-------
    # query_string = '?metadata[keyvalues]={"deck_id":{"value":"' + data['deck_id'] + '","op":"eq"}}'
    # req = requests.get(pinata_pin_list + query_string, headers=pinata_api_headers)
    # pinata_data = json.loads(req.text)
    # if pinata_data['edited'] > deck_to_update.edited and pinata_data['edited'] > data['edited']:
        # deck_to_update... = pinata_data['...']
        # db.session.commit()

    # check edited date isn't older than one in database, if it is, return newest
    if data['edited'] > deck_to_update.edited: # and data['edited'] > pinata_data['edited']:
        if 'deck' in data:
            deck_to_update.deck = data['deck']
        if 'title' in data:
            deck_to_update.title = data['title']
        if 'edited' in data:
            deck_to_update.edited = data['edited']
        if 'deck_cid' in data:
            deck_to_update.deck_cid = data['deck_cid']
        db.session.commit()
        return jsonify({'message': 'Up to date'})
    # else return the database version saved as deck_to_update

    # then if the pinata version wasn't the newest, upload to pinata
    # if pinata_data['edited'] < deck_to_update.edited or pinata_data['edited'] < data['edited']:
    json_data_for_API = {}
    json_data_for_API["pinataMetadata"] = {
        "name": deck_to_update.title,
        "keyvalues": {"deck_id": deck_to_update.deck_id, "edited": deck_to_update.edited}
        }
    json_data_for_API["pinataContent"] = deck_schema.dump(deck_to_update)
    req = requests.post(pinata_json_url, json=json_data_for_API, headers=pinata_api_headers)
    pinata_api_response = json.loads(req.text)
    print("uploaded deck to IPFS. Hash: " + pinata_api_response["IpfsHash"])
    sys.stdout.flush()
    deck_cid = pinata_api_response["IpfsHash"]
    deck_to_update.deck_cid = deck_cid
    db.session.commit()

    return deck_schema.dump(deck_to_update)

@app.route('/delete_deck', methods=['DELETE'])
@cross_origin(origin='*')
@token_required
def delete_deck(current_user):
    data = request.get_json()
    deck = Decks.query.filter_by(deck_id=data['deck_id']).first()

    if not deck:
        return jsonify({'message': 'No deck found!'})

    db.session.delete(deck)
    db.session.commit()

    return jsonify({'message': 'Deck deleted!'})

@app.route('/get_deck_meta', methods=['GET'])
@cross_origin(origin='*')
@token_required
def get_deck_meta(current_user):
    data = request.get_json()
    deck_id = data['deck_id']
    dump = deck_schema.dump(Decks.query.filter_by(deck_id=deck_id).first())
    deck_meta = {
        'title': dump['title'],
        'edited': dump['edited'],
        'deck_cid': dump['deck_cid'],
        'deck_id': dump['deck_id']
    }
    return jsonify(deck_meta)


@app.route('/get_decks_meta', methods=['GET'])
@cross_origin(origin='*')
@token_required
def get_decks_meta(current_user):
    data = request.get_json()
    deck_ids = data['deck_ids']
    decks_meta = []
    for deck_id in deck_ids:
        dump = deck_schema.dump(Decks.query.filter_by(deck_id=deck_id).first())
        deck_meta = {
            'title': dump['title'],
            'edited': dump['edited'],
            'deck_cid': dump['deck_cid'],
            'deck_id': dump['deck_id']
        }
        decks_meta.append(deck_meta)
    return jsonify(decks_meta)


if __name__ == '__main__':
    app.run(debug=True)
