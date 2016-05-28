import flask
import os
import base64
from flask import Flask
import bcrypt
import flask_sqlalchemy
import markdown
from markupsafe import Markup

# need to add voting functionality
# need to sort responses on questions based on votes (high vote gets top of page)
#                       ^-- jinja sort attribute or a sorted query?


app = Flask(__name__)
app.config.from_pyfile('settings.py')
db = flask_sqlalchemy.SQLAlchemy(app)

# Give the site a global name!
site_title = "Stack Overflow 0.5"


# initializing database
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    login = db.Column(db.String(20))
    pw_hash = db.Column(db.String(64))


class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    title = db.Column(db.String(100))
    question_post = db.Column(db.String(150))
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    date = db.Column(db.DATETIME)
    num_answers = db.Column(db.Integer, default=0)  # <-- need to increment that bad boy


class Answers(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    answer_post = db.Column(db.String(150))
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'))
    date = db.Column(db.DATETIME)
    numberUpVotes = db.Column(db.Integer, default=0)
    numberDownVotes = db.Column(db.Integer, default=0)
    up = db.Column(db.BOOLEAN, default=False)
    down = db.Column(db.BOOLEAN, default=False)


class Votes(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    answer = db.Column(db.String(150), db.ForeignKey('answers.answer_post'))
    creator = db.Column(db.Integer, db.ForeignKey('user.id'))
    question = db.Column(db.Integer, db.ForeignKey('question.id'))
    hasCheckedUp = db.Column(db.BOOLEAN, default=False)
    hasCheckedDown = db.Column(db.BOOLEAN, default=False)


db.create_all(app=app)


@app.before_first_request
def startup():
    check = User.query.filter_by(login='admin').first()
    if check is None:
        user = User()
        user.login = 'admin'
        user.pw_hash = bcrypt.hashpw(app.config['ADMIN_PASSWORD'].encode('utf8'), bcrypt.gensalt(15))
        db.session.add(user)
        db.session.commit()


@app.before_request
def setup_token():
    if 'csrf_token' not in flask.session:
        flask.session['csrf_token'] = base64.b64encode(os.urandom(32)).decode('ascii')


@app.before_request
def setup():
    if 'auth_user' in flask.session:
        user = User.query.get(flask.session['auth_user'])
        flask.g.user = user
        if 'auth_user' == 'admin':
            flask.g.user = 'admin'


@app.route('/')
def index():
    questions = Question.query.order_by(Question.date.desc())
    users = User.query.all()
    name = ""
    return flask.make_response(flask.render_template('index.html', csrf_token=flask.session['csrf_token'],
                                                     questions=questions, users=users, name=name,
                                                     site_title=site_title))


@app.route('/login/<state>')
def state_based_login(state):
    return flask.render_template('login.html', state=state, site_title=site_title)


@app.route('/login')
def login():
    return flask.render_template('login.html', site_title=site_title)


@app.route('/new_post')
def new_post():
    if 'auth_user' not in flask.session:
        return flask.redirect(flask.url_for('state_based_login', state=' '), code=303)
    else:
        return flask.render_template('new_post.html', site_title=site_title)


@app.route('/login_user', methods=['POST'])
def check_login():
    ulogin = flask.request.form['user']
    upassword = flask.request.form['password']

    user = User.query.filter_by(login=ulogin).first()
    if user is not None:
        pw_hash = bcrypt.hashpw(upassword.encode('utf8'), user.pw_hash)
        if pw_hash == user.pw_hash:
            flask.session['auth_user'] = user.id
            return flask.redirect('/', code=303)
    return flask.render_template('login.html', state='bad', site_title=site_title)


@app.route('/create_user')
def go_create_user():
    return flask.render_template('create_user.html', site_title=site_title)


@app.route('/create_user', methods=['POST'])
def create_user():
    new_login = flask.request.form['user']
    password = flask.request.form['password']
    pass2 = flask.request.form['confirm']

    if password != pass2:
        return flask.render_template('create_user.html', state='password-mismatch', site_title=site_title)

    existing = User.query.filter_by(login=new_login).first()
    if existing is not None:
        return flask.render_template('create_user.html', state='username-used', site_title=site_title)

    user = User()
    user.login = new_login
    user.pw_hash = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt(15))

    db.session.add(user)
    db.session.commit()

    flask.session['auth_user'] = user.id
    return flask.redirect('/', 303)


@app.route('/logout')
def logout():
    del flask.session['auth_user']
    return flask.redirect('/')


@app.route('/add_post', methods=['POST'])
def addpost():

    user_title = flask.request.form['postTitle']
    user_post = flask.request.form['userPost']

    upost = Question()

    upost.title = user_title
    upost.question_post = user_post
    upost.creator_id = flask.session['auth_user']
    upost.date = db.func.now()

    db.session.add(upost)
    db.session.commit()

    return flask.redirect(flask.url_for('post', post_id=upost.id), code=303)


@app.route('/post/<int:post_id>')
def post(post_id):
    upost = Question.query.get(post_id)
    answers = Answers.query.order_by(Answers.numberUpVotes.desc())
    users = User.query.all()
    votes = Votes.query.filter_by(creator=flask.session['auth_user'], question=upost.id).first()
    # votes = Votes.query.all()
    name = ""
    if Question is None:
        flask.abort(404)
    else:
        content = Markup(markdown.markdown(upost.question_post, output_format='html5'))
        return flask.render_template('display_post.html', post=upost, content=content,
                                     answers=answers, users=users, name=name,
                                     site_title=site_title, votes=votes, user=flask.session['auth_user'])


@app.route('/view_posts')
def view_posts():
    all_users = User.query.all()
    all_questions = Question.query.all()
    return flask.render_template('display_posts.html', questions=all_questions, users=all_users, site_title=site_title)


@app.route('/submit_answer/<int:question_id>/', methods=['POST'])
def submit_answer(question_id):

    # answer shit
    upost = Answers()
    upost.answer_post = flask.request.form['response']
    upost.creator_id = flask.session['auth_user']
    upost.question_id = question_id
    upost.date = db.func.now()

    # increment number of answers on the question
    question = Question.query.get(question_id)
    question.num_answers = Question.num_answers + 1

    db.session.add(upost, question)
    db.session.add(question)
    db.session.commit()
    return flask.redirect(flask.url_for('post', post_id=question_id), code=303)


# the handlers for updating thumbs. it el worko.

@app.route('/update-dat-thumbs-down', methods=['POST'])
def update_thumbs_down():
    if 'auth_user' not in flask.session:
        flask.abort(403)

    creator = flask.session['auth_user']
    if flask.request.form['_csrf_token'] != flask.session['csrf_token']:
        flask.abort(400)

    answer = flask.request.form['answer_id']
    question = flask.request.form['question_id']
    want_thumb = flask.request.form['want_vote'] == 'true'

    thumbs_down = Votes.query.filter_by(question=question, creator=creator, answer=answer).first()
    counter = Answers.query.get(answer)

    if want_thumb:
        if thumbs_down is None:
            thumbs_down = Votes()
            thumbs_down.answer = answer
            thumbs_down.creator = creator
            thumbs_down.question = question

            # if they haven't already checked the box.. check it
            if not thumbs_down.hasCheckedDown:
                thumbs_down.hasCheckedDown = True
                counter.down = True
                # increment dat doee
                counter.numberDownVotes = Answers.numberDownVotes + 1

            db.session.add(thumbs_down, counter)
            db.session.commit()

            flask.jsonify({'result': 'ok'})
            return flask.redirect(flask.url_for('post', post_id=question), code=303)
        else:
            thumbs_down.hasCheckedDown = False
            counter.down = False
            counter.numberDownVotes = Answers.numberDownVotes - 1

            flask.jsonify({'result': "Tried to down something that's already down'd"})
            return flask.redirect(flask.url_for('post', post_id=question), code=303)
    else:
        if thumbs_down is not None:

            counter = Answers.query.get(answer)
            counter.numberDownVotes = Answers.numberDownVotes - 1
            counter.down = False
            thumbs_down.hasCheckedDown = False

            db.session.delete(thumbs_down)
            db.session.commit()
            flask.jsonify({'result': 'ok'})
            return flask.redirect(flask.url_for('post', post_id=question), code=303)
    return flask.redirect(flask.url_for('post', post_id=question), code=303)


@app.route('/update-dat-thumbs-up', methods=['POST'])
def update_thumbs_up():
    if 'auth_user' not in flask.session:
        flask.abort(403)

    creator = flask.session['auth_user']
    if flask.request.form['_csrf_token'] != flask.session['csrf_token']:
        flask.abort(400)

    answer = flask.request.form['answer_id']
    question = flask.request.form['question_id']
    want_thumb = flask.request.form['want_vote'] == 'true'

    thumbs_up = Votes.query.filter_by(question=question, creator=creator, answer=answer).first()
    counter = Answers.query.get(answer)

    if want_thumb:
        if thumbs_up is None:
            thumbs_up = Votes()
            thumbs_up.answer = answer
            thumbs_up.creator = creator
            thumbs_up.question = question

            # if they haven't already checked the box.. check it
            if not thumbs_up.hasCheckedUp:
                thumbs_up.hasCheckedUp = True
                counter.up = True
                # increment dat doee
                counter.numberUpVotes = Answers.numberUpVotes + 1

            db.session.add(thumbs_up, counter)
            db.session.commit()
            flask.jsonify({'result': 'ok'})
            return flask.redirect(flask.url_for('post', post_id=question), code=303)
        else:
            thumbs_up.hasCheckedUp = False
            counter.up = False
            counter.numberUpVotes = Answers.numberUpVotes - 1

            flask.jsonify({'result': "Tried to up something that's already up'd"})
            return flask.redirect(flask.url_for('post', post_id=question), code=303)
    else:
        if thumbs_up is not None:

            # decrement the number of up votes after removing the thumb.
            counter = Answers.query.get(answer)
            counter.numberUpVotes = Answers.numberUpVotes - 1
            counter.up = False
            thumbs_up.hasCheckedUp = False

            db.session.delete(thumbs_up)
            db.session.commit()
            flask.jsonify({'result': 'ok'})
            return flask.redirect(flask.url_for('post', post_id=question), code=303)
    return flask.redirect(flask.url_for('post', post_id=question), code=303)


if __name__ == '__main__':
    app.run()
