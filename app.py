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
from flask_cors import CORS, cross_origin
# remember to include uswgi, psycopg2, marshmallow-sqlalchemy in reqs.txt, also bcrypt==3.1.7 which pipreqs gets wrong:
# psycopg2_binary==2.8.3
# marshmallow-sqlalchemy==0.19.0
# bcrypt==3.1.7
# psycopg2==2.8.4
# uwsgi==2.0.18

app = Flask(__name__)
ma = Marshmallow(app)
CORS(app)
app.debug = True
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['DATABASE_URL']
app.config['SECRET_KEY'] = 'totally%@#$%^T@#Secure!'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


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
        self.deck_id = deck_id
        self.edited = edited
        self.deck_cid = deck_cid
        self.deck = deck
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
        user_collection = UserCollections.query.filter_by(user_id=user.user_id).first()

        # Get decks metadata
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

        # Preload up to 10 decks here..... just get them all, up to 100? do speed tests to decide
        decks = []

        if len(deck_ids) <= 10:
            for deck_id in deck_ids:
                dump = deck_schema.dump(Decks.query.filter_by(deck_id=deck_id).first())
                decks.append(dump['deck'])
        else:
            deck_ids.sort(reverse=True)
            for i in range(10):
                dump = deck_schema.dump(Decks.query.filter_by(deck_id=deck_ids[i]).first())
                decks.append(dump['deck'])

        login_return_data = {'user_collection': user_collection_schema.dump(user_collection),
                             'token': token.decode('UTF-8'),
                             'decks_meta': decks_meta,
                             'decks': decks}

        return jsonify(login_return_data)

    return jsonify({"error": "Invalid credentials"})


# added this create user collection to sign up. leaving this just in case
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


@app.route('/post_deck', methods=['POST'])
@cross_origin(origin='*')
@token_required
def post_deck(current_user):
    data = request.get_json()
    exists = Decks.query.filter_by(deck_id=data['deck_id']).first()
    if exists is not None:
        return jsonify({"error": "Deck already exists"})
    else:
        new_deck = Decks(
            deck_id=data['deck_id'],
            deck=data['deck'],
            # these echo 'deck' internal info to allow for less expensive database metadata queries
            title=data['title'],
            edited=data['edited'],
            deck_cid=data['deck_cid']
        )
        db.session.add(new_deck)
        db.session.commit()
        return deck_schema.dump(new_deck)


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


@app.route('/put_deck', methods=['PUT'])
@cross_origin(origin='*')
@token_required
def put_deck(current_user):
    data = request.get_json()
    deck_update = Decks.query.filter_by(deck_id=data['deck_id']).first()

    if 'deck' in data:
        deck_update.deck = data['deck']
    # If the deck is changed server-side remember to change edited and title in deck itself !!!
    if 'title' in data:
        deck_update.title = data['title']
    if 'edited' in data:
        deck_update.edited = data['edited']
    if 'deck_cid' in data:
        deck_update.deck_cid = data['deck_cid']

    db.session.commit()
    return deck_schema.dump(deck_update)

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
