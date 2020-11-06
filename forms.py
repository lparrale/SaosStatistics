from wtforms import Form
from wtforms import StringField, TextField, PasswordField
from wtforms import validators
class LoginForm(Form):
    server=StringField('Server',[validators.required(),validators.URL(message="Invalid URL")],render_kw={"placeholder": "Server URL"})
    username=StringField('User',[validators.required()], render_kw={"placeholder": "Username"})
    password=PasswordField('Password',[validators.required()],render_kw={"placeholder": "Password"})
    
class CSVForm(Form):
    class Meta:
        csrf = False
    pass
class DRangeForm(Form):
    datetimes=StringField('datetimes',[validators.required()],render_kw={"type":"text", "size":"40"})
    class Meta:
        csrf = False
    
    