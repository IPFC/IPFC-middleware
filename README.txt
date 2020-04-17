# The IPFC middlware server, REST API
Built with Python Flask and Flask-SQLAlchemy. 
https://pypi.org/project/Flask-SQLAlchemy/
Pulls data from a PostgreSQL server
for local testing, download repository, then:

### To run, in terminal:
`python3 -m venv ipfc-middleware`

### Activate the virtualenv (OS X & Linux)
`source ipfc-middleware/bin/activate`

### Activate the virtualenv (Windows)
`ipfc-middleware\Scripts\activate`

### then
`pip install -r requirements.txt`
(or pip3)
`pip3 install -r requirements.txt`

### comment out this line in app.py
`app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['DATABASE_URL']`
### also in app.py change database credentials: (heroku also provides this in resources page)
  Format:
  `dialect+driver://username:password@host:port/database`
  Example Postgres:
  `postgresql://scott:tiger@localhost/mydatabase`

  # remember to delete secret credentials before uploading to github
  # remember to change the serverURL in the javascript files
  
### run in terminal with
`python3 app.py`


### bug: AttributeError: module 'bcrypt._bcrypt' has no attribute 'ffi'
`pip3 uninstall -y -r requirements.txt` 
`pip3 install -r requirements.txt`

if that doesn't work, then 
`pip freeze > requirements1.txt`
`pip3 uninstall -y -r requirements1.txt` 
`pip3 install -r requirements.txt`
then delete requirements1.txt