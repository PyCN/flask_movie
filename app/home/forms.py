# coding: utf8

from flask import  session
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, FileField, SubmitField, TextAreaField
from wtforms.validators import ValidationError, DataRequired, EqualTo, Regexp
import uuid
from app.models import User
from werkzeug.security import check_password_hash


class ResignForm(FlaskForm):
    name = StringField(
        label='昵称',
        validators=[
            DataRequired('请输入昵称')
        ],
        description='昵称',
        render_kw={
            "class": "form-control",
            "placeholder": "请输入昵称！",
        }
    )
    pwd = PasswordField(
        label='密码',
        validators=[
            DataRequired('请输入密码')
        ],
        description='密码',
        render_kw={
            "class": "form-control",
            "placeholder": "请输入密码！",
        }
    )
    repwd = PasswordField(
        label='确认密码',
        validators=[
            DataRequired('请确认密码'),
            EqualTo('pwd', message='两次密码不一致！')
        ],
        description='确认密码',
        render_kw={
            "class": "form-control",
            "placeholder": "请确认密码！",
        }
    )
    email = StringField(
        label='邮箱',
        validators=[
            DataRequired('请输入邮箱')
        ],
        description='邮箱',
        render_kw={
            "class": "form-control",
            "placeholder": "请输入邮箱！"
        }
    )
    phone = StringField(
        label="电话",
        validators=[
            DataRequired('请输入电话'),
            Regexp('1[3458]\d{9}', message='电话格式不正确!')
        ],
        description='电话',
        render_kw={
            "class": "form-control",
            "placeholder": "请输入电话！",
        }
    )
    submit = SubmitField(
        label="注册",
        render_kw={
            "class": "btn btn-lg btn-success btn-block"
        }
    )

    def validate_name(self, field):
        name = field.data
        user = User.query.filter_by(name=name).count()
        if user > 0:
            raise ValidationError("昵称已经存在！")

    def validate_email(self, field):
        email = field.data
        user = User.query.filter_by(email=email).count()
        if user > 0:
            raise ValidationError("邮箱已经存在！")

    def validate_phone(self, field):
        phone = field.data
        user = User.query.filter_by(phone=phone).count()
        if user > 0:
            raise ValidationError("电话已经存在！")


class LoginForm(FlaskForm):
    name = StringField(
        label='账号',
        validators=[
            DataRequired('请输入账号')
        ],
        description='账号',
        render_kw={
            "class": "form-control",
            "placeholder": "请输入账号！",
        }
    )
    pwd = PasswordField(
        label='密码',
        validators=[
            DataRequired('请输入密码')
        ],
        description='密码',
        render_kw={
            "class": "form-control",
            "placeholder": "请输入密码！",
        }
    )
    submit = SubmitField(
        label="登录",
        render_kw={
            "class": "btn btn-lg btn-primary btn-block"
        }
    )


class UserDetailForm(FlaskForm):
    name = StringField(
        label='昵称',
        validators=[
            DataRequired('请输入昵称！')
        ],
        description='昵称',
        render_kw={
            "class": "form-control",
            "placeholder": "请输入昵称！",
        }
    )
    email = StringField(
        label='邮箱',
        validators=[
            DataRequired('请输入邮箱！')
        ],
        description='邮箱',
        render_kw={
            "class": "form-control",
            "placeholder": "请输入邮箱！",
        }
    )
    phone = StringField(
        label='手机',
        validators=[
            DataRequired('请输入手机！')
        ],
        description='手机',
        render_kw={
            "class": "form-control",
            "placeholder": "请输入手机！",
        }
    )
    info = TextAreaField(
        label='简介',
        validators=[
            DataRequired('请输入简介！')
        ],
        description='简介',
        render_kw={
            "class": "form-control",
            "placeholder": "请输入简介！",
        }
    )
    face = FileField(
        label="头像",
        validators=[
            DataRequired("请输入头像！")
        ],
        description="头像"
    )
    submit = SubmitField(
        label="保存",
        render_kw={
            "class": "btn btn-lg btn-primary btn-block"
        }
    )


class PwdForm(FlaskForm):
    old_pwd = PasswordField(
        label='旧密码',
        validators=[
            DataRequired('请输入旧密码！')
        ],
        description='旧密码',
        render_kw={
            "class": "form-control",
            "placeholder": "请输入旧密码！",
        }
    )
    new_pwd = PasswordField(
        label='新密码',
        validators=[
            DataRequired('请输入新密码！')
        ],
        description='新密码',
        render_kw={
            "class": "form-control",
            "placeholder": "请输入新密码！",
        }
    )
    submit = SubmitField(
        "保存",
        render_kw={
            "class": "btn btn-success"
        }
    )

    def validate_old_pwd(self, field):
        pwd = field.data
        user = User.query.get_or_404(session['user_id'])

        if not check_password_hash(user.pwd, pwd):
            raise ValidationError("旧密码不正确！")


class CommentForm(FlaskForm):
    content = TextAreaField(
        label='内容',
        validators=[
            DataRequired('请输入内容！')
        ],
        description='内容',
        render_kw={
            "id": "input_content"
        }
    )
    submit = SubmitField(
        "提交评论",
        render_kw={
            "class": "btn btn-success"
        }
    )