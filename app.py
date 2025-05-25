from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, TextAreaField
from wtforms.validators import DataRequired, Email, Length, Regexp
import os

# Initialize core components
db = SQLAlchemy()
login_manager = LoginManager()

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-123')
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///security_complaints.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'login'

    with app.app_context():
        # Database models
        class User(UserMixin, db.Model):
            id = db.Column(db.Integer, primary_key=True)
            name = db.Column(db.String(100), nullable=False)
            email = db.Column(db.String(100), unique=True, nullable=False)
            phone = db.Column(db.String(20), nullable=False)  # Added phone field
            national_id = db.Column(db.String(20), unique=True, nullable=False)  # Added national ID field
            password = db.Column(db.String(200), nullable=False)
            is_admin = db.Column(db.Boolean, default=False)
            complaints = db.relationship('Complaint', backref='author', lazy=True)

        class Complaint(db.Model):
            id = db.Column(db.Integer, primary_key=True)
            type = db.Column(db.String(50), nullable=False)
            location = db.Column(db.String(200), nullable=False)
            description = db.Column(db.Text, nullable=False)
            status = db.Column(db.String(20), default='جديد')
            created_at = db.Column(db.DateTime, default=datetime.now)
            user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

        # Forms
        class RegistrationForm(FlaskForm):
            name = StringField('الاسم الكامل', validators=[DataRequired()])
            email = StringField('البريد الإلكتروني', validators=[DataRequired(), Email()])
            phone = StringField('رقم الهاتف', validators=[
                DataRequired(),
                Regexp(r'^\+?[0-9]{10,15}$', message='يجب أن يكون رقم الهاتف صالحًا')
            ])
            national_id = StringField('الرقم الوطني', validators=[
                DataRequired(),
                Length(min=10, max=20, message='يجب أن يكون الرقم الوطني بين 10 و20 حرفًا')
            ])
            password = PasswordField('كلمة المرور', validators=[DataRequired(), Length(min=8)])

        class LoginForm(FlaskForm):
            email = StringField('البريد الإلكتروني', validators=[DataRequired(), Email()])
            password = PasswordField('كلمة المرور', validators=[DataRequired()])

        class ComplaintForm(FlaskForm):
            type = SelectField('نوع الشكوى', choices=[
                ('سرقة', 'سرقة'),
                ('اعتداء', 'اعتداء'),
                ('تهديد', 'تهديد'),
                ('خطف', 'خطف'),
                ('قتل', 'قتل'),
                ('حالة أخرى', 'حالة أخرى'),
            ], validators=[DataRequired()])
            location = StringField('الموقع', validators=[DataRequired()])
            description = TextAreaField('تفاصيل الحادثة', validators=[DataRequired()])

        # User loader
        @login_manager.user_loader
        def load_user(user_id):
            return User.query.get(int(user_id))

        # Routes
        @app.route('/')
        def home():
            return render_template('home.html')

        @app.route('/register', methods=['GET', 'POST'])
        def register():
            form = RegistrationForm()
            if form.validate_on_submit():
                # Check if national ID or phone already exists
                if User.query.filter_by(national_id=form.national_id.data).first():
                    flash('الرقم الوطني مسجل بالفعل', 'danger')
                    return redirect(url_for('register'))
                if User.query.filter_by(phone=form.phone.data).first():
                    flash('رقم الهاتف مسجل بالفعل', 'danger')
                    return redirect(url_for('register'))
                
                user = User(
                    name=form.name.data,
                    email=form.email.data,
                    phone=form.phone.data,
                    national_id=form.national_id.data,
                    password=generate_password_hash(form.password.data)
                )
                db.session.add(user)
                db.session.commit()
                flash('تم التسجيل بنجاح! يرجى تسجيل الدخول', 'success')
                return redirect(url_for('login'))
            return render_template('register.html', form=form)

        @app.route('/login', methods=['GET', 'POST'])
        def login():
            form = LoginForm()
            if form.validate_on_submit():
                user = User.query.filter_by(email=form.email.data).first()
                if user and check_password_hash(user.password, form.password.data):
                    login_user(user)
                    return redirect(url_for('dashboard'))
                flash('بيانات الدخول غير صحيحة', 'danger')
            return render_template('login.html', form=form)

        @app.route('/dashboard')
        @login_required
        def dashboard():
            complaints = Complaint.query.filter_by(user_id=current_user.id).all()
            return render_template('dashboard.html', complaints=complaints)

        @app.route('/new-complaint', methods=['GET', 'POST'])
        @login_required
        def new_complaint():
            form = ComplaintForm()
            if form.validate_on_submit():
                complaint = Complaint(
                    type=form.type.data,
                    location=form.location.data,
                    description=form.description.data,
                    user_id=current_user.id
                )
                db.session.add(complaint)
                db.session.commit()
                flash('تم تقديم الشكوى بنجاح', 'success')
                return redirect(url_for('dashboard'))
            return render_template('new_complaint.html', form=form)

        @app.route('/admin')
        @login_required
        def admin_dashboard():
            if not current_user.is_admin:
                abort(403)
            complaints = Complaint.query.all()
            users = User.query.all()
            return render_template('admin_dashboard.html', complaints=complaints, users=users)

        @app.route('/update-status/<int:id>', methods=['POST'])
        @login_required
        def update_status(id):
            if not current_user.is_admin:
                abort(403)
            complaint = Complaint.query.get_or_404(id)
            complaint.status = request.form.get('status')
            db.session.commit()
            flash('تم تحديث حالة الشكوى', 'success')
            return redirect(url_for('admin_dashboard'))

        @app.route('/logout')
        @login_required
        def logout():
            logout_user()
            return redirect(url_for('home'))

        # Create database tables
        db.create_all()

        # إضافة المسؤول الأولي
        if not User.query.filter_by(email='admin@example.com').first():
            admin = User(
                name='Admin',
                email='admin@example.com',
                phone='+1234567890',
                national_id='1234567890',
                password=generate_password_hash('admin123'),
                is_admin=True
            )
            db.session.add(admin)
            db.session.commit()
    
    return app

# Create and run application
app = create_app()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)