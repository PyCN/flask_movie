# coding:utf8

from . import home
from flask import render_template, redirect, url_for, flash, session, request
from app.home.forms import ResignForm, LoginForm, UserDetailForm, PwdForm, CommentForm
from app.models import User, Userlog, Moviecol, Movie, Comment, Tag
from werkzeug.security import generate_password_hash
from werkzeug.utils import secure_filename
import uuid
from app import db, app
from functools import wraps
import os
import datetime
import json


# 登录装饰器
def user_login_req(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for('home.login', next=request.url))
        return f(*args, **kwargs)

    return decorated_function


# 修改文件名称
def change_filename(filename):
    file_info = os.path.splitext(filename)
    filename = datetime.datetime.now().strftime("%Y%m%d%H%M%S") + str(uuid.uuid4().hex) + file_info[-1]
    return filename


@home.route('/')
def index():
    tag_list = Tag.query.all()
    page_data = Movie.query
    tid = request.args.get('tid', 0)
    print(tid)
    if int(tid) != 0:
        page_data = page_data.filter_by(
            tag_id=int(tid)
        )
    star = request.args.get('star', 0)
    if int(star) != 0:
        page_data = page_data.filter_by(
            star=int(star)
        )
    time = request.args.get('time', 0)
    if int(time) != 0:
        page_data = page_data.order_by(
            Movie.addtime.desc()
        )
    else:
        page_data = page_data.order_by(
            Movie.addtime.asc()
        )
    pm = request.args.get("pm", 0)
    if int(pm) != 0:
        page_data = page_data.order_by(
            Movie.playnum.desc()
        )
    else:
        page_data = page_data.order_by(
            Movie.playnum.asc()
        )
    cm = request.args.get("cm", 0)
    if int(cm) != 0:
        page_data = page_data.order_by(
            Movie.commentnum.desc()
        )
    else:
        page_data = page_data.order_by(
            Movie.commentnum.asc()
        )
    page = request.args.get('page')
    if page is None:
        page = 1
    else:
        page = int(page)
    page_data = page_data.paginate(page=page, per_page=10)

    p = dict(
        tid=tid,
        time=time,
        cm=cm,
        pm=pm,
        star=star,
        page=page
    )

    return render_template('home/index.html', tag_list=tag_list, page_data=page_data, p=p)


@home.route('/login/', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        data = form.data
        user = User.query.filter_by(name=data['name']).first()
        if user is None:
            flash("用户不存在！", "err")
            return redirect(url_for('home.login'))
        elif not user.check_pwd(data['pwd']):
            flash('密码不正确！', "err")
            return redirect(url_for('home.login'))

        session['user'] = data['name']
        session['user_id'] = user.id

        userlog = Userlog(
            user_id=user.id,
            ip=request.remote_addr
        )
        db.session.add(userlog)
        db.session.commit()
        return redirect(url_for('home.user'))
    return render_template('home/login.html', form=form)


@home.route('/logout/')
def logout():
    session.pop('user', None)
    session.pop('user_id', None)
    return redirect(url_for('home.login'))


@home.route('/register/', methods=['GET', 'POST'])
def register():
    form = ResignForm();
    if form.validate_on_submit():
        data = form.data
        user = User(
            name=data['name'],
            phone=data['phone'],
            pwd=generate_password_hash(data['pwd']),
            email=data['email'],
            uuid=uuid.uuid4().hex
        )
        db.session.add(user)
        db.session.commit()
        flash("注册会员成功！", "ok")
    return render_template('home/register.html', form=form)


@home.route('/user/', methods=['GET', 'POST'])
@user_login_req
def user():
    form = UserDetailForm()
    user = User.query.get_or_404(int(session['user_id']))
    form.face.validators = []
    if request.method == "GET":
        form.name.data = user.name
        form.email.data = user.email
        form.phone.data = user.phone
        form.face.data = user.face
        form.info.data = user.info
    if form.validate_on_submit():
        data = form.data
        file_face = secure_filename(form.face.data.filename)
        if not os.path.exists(app.config['FC_DIR']):
            os.mkdir(app.config['FC_DIR'])
            os.chmod(app.config['FC_DIR'], 'rw')
        user.face = change_filename(file_face)
        form.face.data.save(app.config['FC_DIR'] + user.face)

        name_count = User.query.filter_by(name=data['name']).count()
        if data['name'] != user.name and name_count > 0:
            flash("该用户名已存在！", "err")
            return redirect(url_for('home.user'))
        phone_count = User.query.filter_by(phone=data['phone']).count()
        if data['phone'] != user.phone and phone_count > 0:
            flash("该手机已存在！", "err")
            return redirect(url_for('home.user'))
        email_count = User.query.filter_by(email=data['email']).count()
        if data['email'] != user.email and email_count > 0:
            flash("该手机已存在！", "err")
            return redirect(url_for('home.user'))

        user.name = data['name']
        user.phone = data['phone']
        user.email = data['email']
        user.info = data['info']
        db.session.add(user)
        db.session.commit()
        flash("修改成功", "ok")
        return redirect(url_for('home.user'))
    return render_template('home/user.html', form=form, user=user)


@home.route('/pwd/', methods=['GET', 'POST'])
@user_login_req
def pwd():
    form = PwdForm()
    if form.validate_on_submit():
        data = form.data
        user = User.query.get_or_404(int(session['user_id']))
        from werkzeug.security import generate_password_hash
        user.pwd = generate_password_hash(data['new_pwd'])
        db.session.add(user)
        db.session.commit()
        flash('修改密码成功！', 'ok')
    return render_template('home/pwd.html', form=form)


@home.route('/comments/<int:page>', methods=['GET'])
@user_login_req
def comments(page=None):
    if page is None:
        page = 1
    page_data = Comment.query.join(
        User
    ).filter(
        User.id == Comment.user_id,
        Comment.user_id == session['user_id']
    ).order_by(
        Comment.addtime.desc()
    ).paginate(page=page, per_page=10)
    return render_template('home/comments.html', page_data=page_data)


@home.route('/loginlog/<int:page>', methods=['GET'])
@user_login_req
def loginlog(page=None):
    if page is None:
        page = 1
    page_data = Userlog.query.filter(
        Userlog.user_id == session['user_id']
    ).order_by(
        Userlog.addtime.desc()
    ).paginate(page=page, per_page=10)
    return render_template('home/loginlog.html', page_data=page_data)


@home.route('/moviecol/<int:page>/', methods=['GET'])
@user_login_req
def moviecol(page=None):
    if page is None:
        page = 1
    page_data = Moviecol.query.join(
        Movie
    ).filter(
        Moviecol.user_id == session['user_id'],
        Movie.id == Moviecol.movie_id
    ).order_by(
        Moviecol.addtime.desc()
    ).paginate(page=page, per_page=10)
    return render_template('home/moviecol.html', page_data=page_data)


@home.route('/animation/')
def animation():
    return render_template('home/animation.html')


@home.route('/search/<int:page>', methods=["GET"])
@user_login_req
def search(page=None):
    key = request.args.get('key')
    if page is None:
        page = 1
    page_data = Movie.query.filter(
        Movie.title.ilike('%' + key + '%')
    ).order_by(
        Movie.addtime.desc()
    ).paginate(page=page, per_page=10)
    page_count = Movie.query.filter(
        Movie.title.ilike("%" + key + "%")
    ).count()
    return render_template('home/search.html', page_data=page_data, key=key, page_count=page_count)


@home.route('/play/<int:id>/<int:page>', methods=['GET', 'POST'])
@user_login_req
def play(id=None, page=None):
    movie = Movie.query.join(Tag).filter(
        Tag.id == Movie.tag_id,
        Movie.id == int(id)
    ).first_or_404()

    # 进入页面，播放量加1
    movie.playnum = movie.playnum + 1

    if page is None:
        page = 1

    page_data = Comment.query.filter_by(
        movie_id=int(id)
    ).join(
        Movie,
        User
    ).filter(
        Movie.id == Comment.movie_id,
        User.id == Comment.user_id
    ).order_by(
        Comment.addtime.desc()
    ).paginate(page=page, per_page=10)
    # 计算评论数量
    comment_count = Comment.query.filter_by(movie_id=int(id)).count()
    # 处理添加评论
    form = CommentForm()
    if form.validate_on_submit():
        data = form.data
        comment = Comment(
            user_id=int(session['user_id']),
            content=data['content'],
            movie_id=movie.id
        )
        db.session.add(comment)
        db.session.commit()
        movie.commentnum = movie.commentnum + 1
        flash("添加评论成功！", "ok")
        return redirect(url_for('home.play', id=int(id), page=1))

    db.session.add(movie)
    db.session.commit()
    return render_template('home/play.html', movie=movie, page_data=page_data, comment_count=comment_count, form=form)


@home.route('/moviecol_add/', methods=['GET'])
@user_login_req
def moviecol_add():
    mid = request.args.get('mid', '')
    uid = request.args.get('uid', '')

    moviecol_count = Moviecol.query.filter_by(
        movie_id=int(mid),
        user_id=int(session['user_id'])
    ).count()
    print(moviecol_count)
    if moviecol_count > 0:
        return json.dumps(dict(
            code=409,
            message="该电影已经被收藏！"
        ))
    else:
        moviecol = Moviecol(
            movie_id=mid,
            user_id=uid
        )
        db.session.add(moviecol)
        db.session.commit()
        return json.dumps(dict(
            code=200,
            message="收藏成功！"
        ))
