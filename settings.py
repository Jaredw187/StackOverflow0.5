from p3 import app
SECRET_KEY = 'asdjhflahslfdjskdhf19283798asjhfcnba'
ADMIN_PASSWORD = 'thisisareallybadpassword'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
#SQLALCHEMY_ECHO = True
