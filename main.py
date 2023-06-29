from flask import Flask, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from sqlalchemy import Table, Column, Integer, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps
import bleach
import os

# List of allowed HTML tags
ALLOWED_TAGS = ['p', 'b', 'i', 'u', 'em', 'strong', 'a']


def clean_html(html):
    # Clean the HTML, allowing only the tags in ALLOWED_TAGS
    cleaned_html = bleach.clean(html, tags=ALLOWED_TAGS, strip=True)

    return cleaned_html


Base = declarative_base()


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.id or current_user.id != 1:  # If user is not admin, redirect to login page
            return "Error 404: Access Denied"
        return f(*args, **kwargs)  # If user is admin, proceed as usual

    return decorated_function


login_manager = LoginManager()
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
ckeditor = CKEditor(app)
Bootstrap(app)
login_manager.init_app(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


##CONFIGURE TABLES

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    user_id = db.Column(db.Integer, ForeignKey('users.id'))
    user = relationship('User', back_populates='blog_posts')
    comments = relationship('Comment', back_populates="blog_post")


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), nullable=False, unique=True)
    password_hash = db.Column(db.String(250), nullable=False)
    blog_posts = relationship('BlogPost', back_populates="user")
    comments = relationship('Comment', back_populates='user')


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, ForeignKey('users.id'))
    user = relationship('User', back_populates='comments')
    blogpost_id = Column(Integer, ForeignKey('blog_posts.id'))
    blog_post = relationship('BlogPost', back_populates='comments')


db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    if current_user.is_authenticated:
        user_id = current_user.id
        print(user_id)
        return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated, user_id=user_id)
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=['POST', 'GET'])
def register():
    form = RegisterForm()
    user = User()
    if request.method == 'POST':
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash('You have already signed up with this email, login instead!')
            return redirect(url_for('login'))
        else:
            user.name = form.name.data
            user.email = form.email.data
            user.password_hash = generate_password_hash(form.password.data, salt_length=8)
            db.session.add(user)
            db.session.commit()
            login_user(user)

            return redirect(url_for('get_all_posts'))

    return render_template("register.html", form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    user = User.query.filter_by(email=form.email.data).first()

    if request.method == 'POST':

        if not user:
            flash('Invalid username.')
            return redirect(url_for('login'))

        elif not check_password_hash(user.password_hash, form.password.data):
            flash('Invalid password.')
            return redirect(url_for('login'))

        else:
            login_user(user)
            return redirect(url_for('get_all_posts'))
    return render_template("login.html", logged_in=current_user.is_authenticated, form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    comment_form = CommentForm()
    if current_user.is_authenticated and comment_form.validate_on_submit():
        new_comment = Comment(
            user_id=current_user.id,
            text=clean_html(comment_form.comment.text),
            blogpost_id=post_id
        )
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for('show_post', post_id=post_id))
    elif not current_user.is_authenticated and request.method == 'POST':
        flash('You need to log in to leave a comment')

        return redirect(url_for('login'))

    return render_template("post.html",
                           post=requested_post,
                           logged_in=current_user.is_authenticated,
                           user_id=current_user.id if current_user.is_authenticated else None,
                           form=comment_form)


@app.route("/about")
def about():
    return render_template("about.html", logged_in=current_user.is_authenticated)


@app.route("/contact")
def contact():
    return render_template("contact.html", logged_in=current_user.is_authenticated)


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            user_id=current_user.id,
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=clean_html(form.body.data),
            img_url=form.img_url.data,

            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, logged_in=current_user.is_authenticated)


@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, logged_in=current_user.is_authenticated)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/delete-comment/<int:post_id>/<int:comment_id>", methods=["GET", "POST"])
@login_required
def delete_comment(post_id, comment_id):
    comment_to_delete = Comment.query.get(comment_id)
    db.session.delete(comment_to_delete)
    db.session.commit()
    return redirect(url_for('show_post', post_id=post_id))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5002, debug=True)
