# coding:utf8

from . import admin
from flask import render_template, redirect, url_for, flash, session, request, abort
from app.admin.forms import LoginForm, TagForm, MovieForm, PreviewForm, PwdForm, AuthForm, RoleForm, AdminForm
from app.models import Admin, Tag, Movie, Preview, User, Comment, Moviecol, Oplog, Adminlog, Userlog, Auth, Role
from functools import wraps
from app import db, app
from werkzeug.utils import secure_filename
import os
import uuid
import datetime


def admin_login_ref(f):
    @wraps(f)
    def decorated_function(*args, **kw):
        if "account" not in session:
            return redirect(url_for('admin.login', next=request.url))
        return f(*args, **kw)

    return decorated_function


def admin_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        current_admin = db.session.query(Admin, Role).outerjoin(Role).filter(
                        Role.id == Admin.role_id,
                        Admin.id == session["admin_id"]
        ).first()
        if current_admin.Admin.is_super == 1:
            auths = current_admin.Role.auths
            if auths:
                auths = list(map(lambda v: int(v), auths.split(",")))
                auth_list = Auth.query.all()
                urls = [v.url for v in auth_list for val in auths if val == v.id]
                rule = request.url_rule
                if str(rule) not in urls:
                    abort(404)
                return f(*args, **kwargs)
            abort(404)
        return f(*args, **kwargs)
    return decorated_function


def change_filename(filename):
    fileinfo = os.path.splitext(filename)
    filename = datetime.datetime.now().strftime("%Y%m%d%H%M%S") + str(uuid.uuid4().hex) + fileinfo[-1]
    return filename


@admin.route('/')
@admin_login_ref
def index():
    return render_template('admin/index.html')


@admin.route('/login/', methods=["POST", "GET"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        data = form.data
        admin = Admin.query.filter_by(name=data['account']).first()

        if not admin.check_pwd(data['pwd']):
            flash("密码错误！")
            return redirect(url_for("admin.login"))

        session['account'] = data['account']
        session['admin_id'] = admin.id

        admin_log = Adminlog(
            admin_id=session['admin_id'],
            ip=request.remote_addr
        )
        db.session.add(admin_log)
        db.session.commit()
        return redirect(request.args.get('next') or url_for('admin.index'))
    return render_template('admin/login.html', form=form)


@admin.route('/logout/')
@admin_login_ref
def logout():
    session.pop('account', None)
    session.pop('admin_id', None)
    return redirect(url_for('admin.login'))


@admin.route('/pwd/', methods=['GET', 'POST'])
@admin_login_ref
def pwd():
    form = PwdForm()
    if form.validate_on_submit():
        data = form.data
        admin = Admin.query.filter_by(
            name=session['account']
        ).first()
        from werkzeug.security import generate_password_hash
        admin.pwd = generate_password_hash(data['new_pwd'])
        db.session.add(admin)
        db.session.commit()
        flash("修改密码成功！", "ok")
        return redirect(url_for('admin.logout'))
    return render_template('admin/pwd.html', form=form)


@admin.route('/tag/add', methods=['GET', 'POST'])
@admin_login_ref
@admin_auth
def tag_add():
    form = TagForm()
    if form.validate_on_submit():
        data = form.data
        tag = Tag.query.filter_by(name=data['name']).count()
        if tag > 0:
            flash("该标签名称已经存在！", "err")
            return redirect(url_for('admin.tag_add'))

        tag = Tag(
            name=data['name']
        )

        db.session.add(tag)
        db.session.commit()
        flash("添加标签成功！", "ok")

        oplog = Oplog(
            admin_id=session['admin_id'],
            ip=request.remote_addr,
            reason="添加标签<%s>" % data['name']
        )
        db.session.add(oplog)
        db.session.commit()
        return redirect(url_for('admin.tag_add'))
    return render_template('admin/tag_add.html', form=form)


@admin.route('/tag/edit/<int:id>/', methods=['GET', 'POST'])
@admin_login_ref
@admin_auth
def tag_edit(id=None):
    form = TagForm()
    tag = Tag.query.get_or_404(id)
    if form.validate_on_submit():
        data = form.data
        tag_count = Tag.query.filter_by(name=data['name']).count()
        if data['name'] == tag.name and tag_count > 0:
            flash("该标签名称已经存在！", "err")
            return redirect(url_for('admin.tag_edit', id=id))

        tag.name = data['name']
        db.session.add(tag)
        db.session.commit()
        flash("标签修改成功！", "ok")

        op_log = Oplog(
            admin_id=session['admin_id'],
            ip=request.remote_addr,
            reason="编辑标签<%s>" % tag['name']
        )
        db.session.add(op_log)
        db.session.commit()
        return redirect(url_for('admin.tag_edit', id=id))

    return render_template('admin/tag_edit.html', form=form, tag=tag)


@admin.route('/tag/list/<int:page>/', methods=['GET'])
@admin_login_ref
@admin_auth
def tag_list(page=None):
    if page is None:
        page = 1
    page_data = Tag.query.order_by(
        Tag.addtime.desc()
    ).paginate(page=page, per_page=10)
    return render_template('admin/tag_list.html', page_data=page_data)


@admin.route('/tag/del/<int:id>/', methods=['GET'])
@admin_login_ref
@admin_auth
def tag_del(id=None):
    tag = Tag.query.filter_by(id=id).first_or_404()
    db.session.delete(tag)
    db.session.commit()
    flash('删除标签成功！', 'ok')

    op_log = Oplog(
        admin_id=session['admin_id'],
        ip=request.remote_addr,
        reason="删除标签<%s>" % tag.name
    )
    db.session.add(op_log)
    db.session.commit()
    return redirect(url_for('admin.tag_list', page=1))


@admin.route('/movie/add', methods=["GET", "POST"])
@admin_login_ref
@admin_auth
def movie_add():
    form = MovieForm()
    if form.validate_on_submit():
        data = form.data
        file_url = secure_filename(form.url.data.filename)
        file_logo = secure_filename(form.logo.data.filename)

        if not os.path.exists(app.config['UP_DIR']):
            os.makedirs(app.config["UP_DIR"])
            os.chmod(app.config['UP_DIR'], "rw")

        url = change_filename(file_url)
        logo = change_filename(file_logo)
        form.url.data.save(app.config['UP_DIR'] + url)
        form.logo.data.save(app.config['UP_DIR'] + logo)

        movie = Movie(
            title=data['title'],
            url=url,
            info=data['info'],
            logo=logo,
            star=int(data['star']),
            playnum=0,
            commentnum=0,
            tag_id=int(data['tag_id']),
            area=data['area'],
            release_time=data['release_time'],
            length=data['length']
        )

        db.session.add(movie)
        db.session.commit()
        flash("添加电影成功！", "ok")

        op_log = Oplog(
            admin_id=session['admin_id'],
            ip=request.remote_addr,
            reason="添加电影<%s>" % data['title']
        )
        db.session.add(op_log)
        db.session.commit()

        return redirect(url_for('admin.movie_add'))

    return render_template('admin/movie_add.html', form=form)


@admin.route('/movie/list/<int:page>/', methods=["GET"])
@admin_login_ref
@admin_auth
def movie_list(page=None):
    if page == None:
        page = 1
    page_data = Movie.query.join(Tag).filter(
        Tag.id == Movie.tag_id
    ).order_by(
        Movie.addtime.desc()
    ).paginate(page=page, per_page=10)
    return render_template('admin/movie_list.html', page_data=page_data)


@admin.route('movie/del/<int:id>/', methods=['GET'])
@admin_login_ref
@admin_auth
def movie_del(id=None):
    movie = Movie.query.get_or_404(int(id))
    db.session.delete(movie)
    db.session.commit()
    flash("删除电影成功！", "ok")

    op_log = Oplog(
        admin_id=session['admin_id'],
        ip=request.remote_addr,
        reason="删除电影<%s>" % movie['name']
    )
    db.session.add(op_log)
    db.session.commit()
    return redirect(url_for('admin.movie_list', page=1))


@admin.route('movie/edit/<int:id>/', methods=['GET', 'POST'])
@admin_login_ref
@admin_auth
def movie_edit(id=None):
    form = MovieForm()
    form.url.validators = []
    form.logo.validators = []

    movie = Movie.query.get_or_404(int(id))
    if request.method == 'GET':
        form.info.data = movie.info
        form.tag_id.data = movie.tag_id
        form.star.data = movie.star

    if form.validate_on_submit():
        data = form.data
        movie_count = Movie.query.filter_by(title=data['title']).count()

        if movie_count > 0 and movie.title != data['title']:
            flash('片名已经存在', 'err')
            return redirect(url_for('admin.movie_edit', id=id))

        if not os.path.exists(app.config['UP_DIR']):
            os.makedirs(app.config["UP_DIR"])
            os.chmod(app.config["UP_DIR"])

        if form.url.data.filename != '':
            file_url = secure_filename(form.url.data.filename)
            movie.url = change_filename(file_url)
            form.url.data.save(app.config['UP_DIR'] + movie.url)
        if form.logo.data.filename != '':
            file_logo = secure_filename(form.logo.data.filename)
            movie.logo = change_filename(file_logo)
            form.logo.data.save(app.config['UP_DIR'] + movie.logo)

        movie.title = data['title']
        movie.info = data['info']
        movie.tag_id = int(data['tag_id'])
        movie.star = int(data['star'])
        movie.area = data['area']
        movie.release_time = data['release_time']
        movie.length = data['length']

        db.session.add(movie)
        db.session.commit()
        flash("编辑电影成功！", "ok")

        op_log = Oplog(
            admin_id=session['admin_id'],
            ip=request.remote_addr,
            reason="编辑电影<%s>" % movie['name']
        )
        db.session.add(op_log)
        db.session.commit()
        return redirect(url_for('admin.movie_edit', id=movie.id))
    return render_template('admin/movie_edit.html', form=form, movie=movie)


@admin.route('/preview/add', methods=["GET", "POST"])
@admin_login_ref
@admin_auth
def preview_add():
    form = PreviewForm()
    if form.validate_on_submit():
        data = form.data
        file_logo = secure_filename(form.logo.data.filename)
        if not os.path.exists(app.config['UP_DIR']):
            os.makedirs(app.config["UP_DIR"])
            os.chmod(app.config["UP_DIR"])

        logo = change_filename(file_logo)
        form.logo.data.save(app.config['UP_DIR'] + logo)
        preview = Preview(
            title=data['title'],
            logo=logo
        )

        db.session.add(preview)
        db.session.commit()
        flash("添加预告成功！", 'ok')

        op_log = Oplog(
            admin_id=session['admin_id'],
            ip=request.remote_addr,
            reason="添加预览<%s>" % data['name']
        )
        db.session.add(op_log)
        db.session.commit()
        return redirect(url_for('admin.preview_add'))

    return render_template('admin/preview_add.html', form=form)


@admin.route('/preview/list/<int:page>', methods=["GET"])
@admin_login_ref
@admin_auth
def preview_list(page=None):
    if page is None:
        page = 1

    page_data = Preview.query.order_by(
        Preview.addtime.desc()
    ).paginate(page=page, per_page=10)
    return render_template('admin/preview_list.html', page_data=page_data)


@admin.route('/preview/eidt/<int:id>/', methods=["GET", "POST"])
@admin_login_ref
@admin_auth
def preview_edit(id=None):
    form = PreviewForm()
    preview = Preview.query.get_or_404(int(id))
    form.logo.validators = []

    if request.method == "GET":
        form.logo.data = preview.logo
    if form.validate_on_submit():
        data = form.data
        preview_logo = secure_filename(form.logo.data.filename)
        if not os.path.exists(app.config['UP_DIR']):
            os.makedirs(app.config["UP_DIR"])
            os.chmod(app.config["UP_DIR"])

        logo = change_filename(preview_logo)
        form.logo.data.save(app.config['UP_DIR'] + logo)
        preview.title = data['title']
        preview.logo = logo
        db.session.add(preview)
        db.session.commit()
        flash("编辑预告成功", 'ok')

        op_log = Oplog(
            admin_id=session['admin_id'],
            ip=request.remote_addr,
            reason="编辑预告<%s>" % preview['title']
        )
        db.session.add(op_log)
        db.session.commit()
        return redirect(url_for('admin.preview_edit', id=id))
    return render_template('admin/preview_edit.html', form=form, preview=preview)


@admin.route('/preview/del/<int:id>', methods=["GET"])
@admin_login_ref
@admin_auth
def preview_del(id=None):
    preview = Preview.query.get_or_404(int(id))
    db.session.delete(preview)
    db.session.commit()
    flash("预告删除成功！", 'ok')

    op_log = Oplog(
        admin_id=session['admin_id'],
        ip=request.remote_addr,
        reason="删除预告<%s>" % preview['title']
    )
    db.session.add(op_log)
    db.session.commit()
    return redirect(url_for('admin.preview_list', page=1))


@admin.route('/user/list/<int:page>/', methods=["GET"])
@admin_login_ref
@admin_auth
def user_list(page=None):
    if page is None:
        page = 1
    page_data = User.query.order_by(
        User.addtime.desc()
    ).paginate(page=page, per_page=10)

    return render_template('admin/user_list.html', page_data=page_data)


@admin.route('/user/view/<int:id>', methods=["GET"])
@admin_login_ref
@admin_auth
def user_view(id=None):
    user = User.query.get_or_404(int(id))
    return render_template('admin/user_view.html', user=user)


@admin.route('/user/del/<int:id>', methods=['GET'])
@admin_login_ref
@admin_auth
def user_del(id=None):
    user = User.query.get_or_404(int(id))
    db.session.delete(user)
    db.session.commit()
    flash("删除会员成功！", "ok")

    op_log = Oplog(
        admin_id=session['admin_id'],
        ip=request.remote_addr,
        reason="删除会员<%s>" % user['name']
    )
    db.session.add(op_log)
    db.session.commit()
    return redirect(url_for('admin.user_list', page=1))


@admin.route('/comment/list/<int:page>/', methods=["GET"])
@admin_login_ref
@admin_auth
def comment_list(page=None):
    if page is None:
        page = 1

    page_data = Comment.query.join(
        Movie
    ).join(
        User
    ).filter(
        Comment.movie_id == Movie.id,
        Comment.user_id == User.id
    ).order_by(
        Comment.addtime.desc()
    ).paginate(page=page, per_page=10)

    return render_template('admin/comment_list.html', page_data=page_data)


@admin.route('/comment/del/<int:id>/', methods=["GET"])
@admin_login_ref
@admin_auth
def comment_del(id=None):
    comment = Comment.query.get_or_404(int(id))
    db.session.delete(comment)
    db.session.commit()
    flash("评论删除成功！", 'ok')

    op_log = Oplog(
        admin_id=session['admin_id'],
        ip=request.remote_addr,
        reason="删除评论<%s>" % comment['id']
    )
    db.session.add(op_log)
    db.session.commit()
    return redirect(url_for('admin.comment_list', page=1))


@admin.route('/moviewcol/list/<int:page>', methods=['GET'])
@admin_login_ref
@admin_auth
def moviecol_list(page=None):
    if page is None:
        page = 1

    page_data = Moviecol.query.join(
        Movie
    ).join(
        User
    ).filter(
        User.id == Moviecol.user_id,
        Movie.id == Moviecol.movie_id
    ).order_by(
        Moviecol.addtime.desc()
    ).paginate(page=page, per_page=10)
    return render_template('admin/moviecol_list.html', page_data=page_data)


@admin.route("moviewcol/del/<int:id>", methods=['GET'])
@admin_login_ref
@admin_auth
def moviecol_del(id=None):
    moviecol = Moviecol.query.get_or_404(int(id))
    db.session.delete(moviecol)
    db.session.commit()
    flash("删除收藏成功", 'ok')
    return redirect(url_for('admin.moviecol_list', page=1))


@admin.route('/oplog/list/<int:page>/', methods=['GET'])
@admin_login_ref
@admin_auth
def oplog_list(page=None):
    if page is None:
        page = 1

    page_data = Oplog.query.join(
        Admin
    ).filter(
        Admin.id == Oplog.admin_id
    ).order_by(
        Oplog.addtime.desc()
    ).paginate(page=page, per_page=10)

    return render_template('admin/oplog_list.html', page_data=page_data)


@admin.route('/adminloginlog/list/<int:page>', methods=["GET"])
@admin_login_ref
@admin_auth
def adminloginlog_list(page=None):
    page_data = Adminlog.query.join(
        Admin
    ).filter(
        Admin.id == Adminlog.admin_id
    ).order_by(
        Adminlog.addtime.desc()
    ).paginate(page=page, per_page=10)
    return render_template('admin/adminloginlog_list.html', page_data=page_data)


@admin.route('/userloginlog/list/<int:page>', methods=["GET"])
@admin_login_ref
@admin_auth
def userloginlog_list(page=None):
    if page is None:
        page = 1

    page_data = Userlog.query.join(
        User
    ).filter(
        Userlog.user_id == User.id
    ).order_by(
        Userlog.addtime.desc()
    ).paginate(page=page, per_page=10)

    return render_template('admin/userloginlog_list.html', page_data=page_data)


@admin.route('/role/add', methods=["GET", "POST"])
@admin_login_ref
@admin_auth
def role_add():
    form = RoleForm()
    if form.validate_on_submit():
        data = form.data
        role = Role(
            name=data['name'],
            auths=','.join(map(lambda v: str(v), data['auths']))
        )
        db.session.add(role)
        db.session.commit()
        flash("添加角色成功！", "ok")
    return render_template('admin/role_add.html', form=form)


@admin.route('/role/list/<int:page>', methods=["GET"])
@admin_login_ref
@admin_auth
def role_list(page=None):
    if page is None:
        page = 1

    page_data = Role.query.order_by(
        Role.addtime.desc()
    ).paginate(page=page, per_page=10)
    return render_template('admin/role_list.html', page_data=page_data)


@admin.route('/role/edit/<int:id>', methods=["GET", "POST"])
@admin_login_ref
@admin_auth
def role_edit(id=None):
    role = Role.query.get_or_404(int(id))
    form = RoleForm()
    if request.method == 'GET':
        form.auths.data = list(map(lambda v: int(v), role.auths.split(',')))

    if form.validate_on_submit():
        data = form.data
        role_count = Role.query.filter_by(
            name=data['name']
        ).count()

        if role_count > 0 and data['name'] != role.name:
            flash("当前角色名已存在！", "err")
            return redirect(url_for('admin.role_edit', id=id))

        role.name = data['name']
        role.auths = ','.join(map(lambda v: str(v), data['auths']))
        db.session.add(role)
        db.session.commit()
        flash("编辑角色成功！", "ok")
    return render_template('admin/role_edit.html', form=form, role=role)


@admin.route('/role/del/<int:id>', methods=['GET'])
@admin_login_ref
@admin_auth
def role_del(id=None):
    role = Role.query.get_or_404(int(id))
    db.session.delete(role)
    db.session.commit()
    flash('删除角色成功！', "ok")
    return redirect(url_for('admin.role_list', page=1))


@admin.route('/auth/add', methods=['GET', 'POST'])
@admin_login_ref
@admin_auth
def auth_add():
    form = AuthForm()
    if form.validate_on_submit():
        data = form.data
        auth = Auth(
            name=data['name'],
            url=data['url']
        )
        db.session.add(auth)
        db.session.commit()
        flash('添加权限成功！', 'ok')
    return render_template('admin/auth_add.html', form=form)


@admin.route('/auth/list/<int:page>', methods=['GET', 'POST'])
@admin_login_ref
@admin_auth
def auth_list(page=None):
    if page is None:
        page = 1
    page_data = Auth.query.order_by(
        Auth.addtime.desc()
    ).paginate(page=page, per_page=10)
    return render_template('admin/auth_list.html', page_data=page_data)


@admin.route('/auth/edit/<int:id>', methods=['GET', 'POST'])
@admin_login_ref
@admin_auth
def auth_edit(id=None):
    auth = Auth.query.get_or_404(int(id))
    form = AuthForm()
    if form.validate_on_submit():
        data = form.data
        auth_count = Auth.query.filter(
            data['name'] == auth.name
        ).count()

        if auth_count > 0 and data['name'] != auth.name:
            flash("当前权限名称已存在！", "err")
            return redirect(url_for('admin.auth_edit', id=id))

        auth.name = data['name']
        auth.url = data['url']
        db.session.add(auth)
        db.session.commit()
        flash('编辑权限成功！', 'ok')
    return render_template('admin/auth_edit.html', form=form)


@admin.route('/auth/del/<int:id>', methods=["GET"])
@admin_login_ref
@admin_auth
def auth_del(id=None):
    auth = Auth.query.get_or_404(int(id))
    db.session.delete(auth)
    db.session.commit()
    flash('删除权限成功', 'ok')
    return redirect(url_for('admin.auth_list', page=1))


@admin.route('/admin/add', methods=['GET', 'POST'])
@admin_login_ref
@admin_auth
def admin_add():
    form = AdminForm()
    if form.validate_on_submit():
        data = form.data
        from werkzeug.security import generate_password_hash
        admin = Admin(
            name=data['name'],
            pwd=generate_password_hash(data['pwd']),
            role_id=data['role_id']
        )
        db.session.add(admin)
        db.session.commit()
        flash("创建管理员成功！", "ok")
    return render_template('admin/admin_add.html', form=form)


@admin.route('/admin/list/<int:page>', methods=["GET"])
@admin_login_ref
@admin_auth
def admin_list(page=None):
    if page is None:
        page = 1
    page_data = Admin.query.join(
        Role
    ).filter(
        Role.id == Admin.role_id
    ).order_by(
        Admin.addtime.desc()
    ).paginate(page=page, per_page=10)
    return render_template('admin/admin_list.html', page_data=page_data)
