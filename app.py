from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///stok.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Association table for role-menu permissions
role_menus = db.Table('role_menus',
    db.Column('role_id', db.Integer, db.ForeignKey('role.id')),
    db.Column('menu_id', db.Integer, db.ForeignKey('menu.id'))
)

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)
    menus = db.relationship('Menu', secondary=role_menus, backref='roles')

class Department(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'))
    department_id = db.Column(db.Integer, db.ForeignKey('department.id'))
    role = db.relationship('Role')
    department = db.relationship('Department')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Menu(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    module = db.Column(db.String(64), nullable=False)
    name = db.Column(db.String(64), nullable=False)

class Stock(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(64), unique=True, nullable=False)
    name = db.Column(db.String(128), nullable=False)
    quantity = db.Column(db.Integer, default=0)
    unit = db.Column(db.String(32))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def init_db():
    db.create_all()
    # create default roles and menus if not exist
    if not Role.query.filter_by(name='Admin').first():
        admin_role = Role(name='Admin')
        db.session.add(admin_role)
        db.session.commit()
    if not Menu.query.first():
        menus = [
            ('Kartlar', 'Stok Kartları'), ('Kartlar', 'Masraf Yeri Kartları'),
            ('Kartlar', 'Lokasyon Kartları'), ('Kartlar', 'Birim Kartları'),
            ('Kartlar', 'Kategori Kartları'), ('Hareketler', 'Talep Girişi'),
            ('Hareketler', 'Fatura Girişi'), ('Hareketler', 'Mal Girişi'),
            ('Hareketler', 'Üretime Çıkış'), ('Raporlar', 'Alım Raporları'),
            ('Raporlar', 'Çıkış Raporları'), ('Raporlar', 'Stok Raporları'),
            ('Yönetim', 'Kullanıcı Ekle'), ('Yönetim', 'Departman Ekle'),
            ('Yönetim', 'Yetki Tanımlama')
        ]
        for module, name in menus:
            db.session.add(Menu(module=module, name=name))
        db.session.commit()
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', role=Role.query.filter_by(name='Admin').first())
        admin.set_password('admin')
        db.session.add(admin)
        db.session.commit()
    if not Stock.query.first():
        sample = Stock(code='STK1', name='Örnek Stok', quantity=10, unit='Adet')
        db.session.add(sample)
        db.session.commit()

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and user.check_password(request.form['password']):
            login_user(user)
            return redirect(url_for('index'))
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Utility decorator to check permission
from functools import wraps

def permission_required(menu_name):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if current_user.role.name == 'Admin':
                return f(*args, **kwargs)
            menu = Menu.query.filter_by(name=menu_name).first()
            if not menu or menu not in current_user.role.menus:
                flash('Yetkiniz yok')
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Management Views
@app.route('/management/users')
@login_required
@permission_required('Kullanıcı Ekle')
def manage_users():
    users = User.query.all()
    roles = Role.query.all()
    departments = Department.query.all()
    return render_template('manage_users.html', users=users, roles=roles, departments=departments)

@app.route('/management/users/add', methods=['POST'])
@login_required
@permission_required('Kullanıcı Ekle')
def add_user():
    username = request.form['username']
    password = request.form['password']
    role_id = request.form.get('role_id')
    department_id = request.form.get('department_id')
    user = User(username=username, role_id=role_id, department_id=department_id)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    return redirect(url_for('manage_users'))

@app.route('/management/users/edit/<int:user_id>', methods=['POST'])
@login_required
@permission_required('Kullanıcı Ekle')
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    user.username = request.form['username']
    if request.form.get('password'):
        user.set_password(request.form['password'])
    user.role_id = request.form.get('role_id')
    user.department_id = request.form.get('department_id')
    db.session.commit()
    return redirect(url_for('manage_users'))

@app.route('/management/users/delete/<int:user_id>')
@login_required
@permission_required('Kullanıcı Ekle')
def delete_user(user_id):
    if current_user.id == user_id:
        flash('Kendi hesabınızı silemezsiniz')
        return redirect(url_for('manage_users'))
    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
    return redirect(url_for('manage_users'))

@app.route('/management/departments')
@login_required
@permission_required('Departman Ekle')
def manage_departments():
    departments = Department.query.all()
    return render_template('manage_departments.html', departments=departments)

@app.route('/management/departments/add', methods=['POST'])
@login_required
@permission_required('Departman Ekle')
def add_department():
    name = request.form['name']
    db.session.add(Department(name=name))
    db.session.commit()
    return redirect(url_for('manage_departments'))

@app.route('/management/departments/edit/<int:dept_id>', methods=['POST'])
@login_required
@permission_required('Departman Ekle')
def edit_department(dept_id):
    dept = Department.query.get_or_404(dept_id)
    dept.name = request.form['name']
    db.session.commit()
    return redirect(url_for('manage_departments'))

@app.route('/management/departments/delete/<int:dept_id>')
@login_required
@permission_required('Departman Ekle')
def delete_department(dept_id):
    dept = Department.query.get(dept_id)
    if dept:
        db.session.delete(dept)
        db.session.commit()
    return redirect(url_for('manage_departments'))

@app.route('/management/permissions', methods=['GET', 'POST'])
@login_required
@permission_required('Yetki Tanımlama')
def manage_permissions():
    roles = Role.query.all()
    menus = Menu.query.all()
    role = None
    if request.method == 'POST':
        role_id = request.form['role_id']
        role = Role.query.get(role_id)
        if 'menus' in request.form:
            selected = request.form.getlist('menus')
            role.menus = [Menu.query.get(int(mid)) for mid in selected]
            db.session.commit()
            return redirect(url_for('manage_permissions'))
    elif request.args.get('role_id'):
        role = Role.query.get(request.args.get('role_id'))
    return render_template('manage_permissions.html', roles=roles, menus=menus, role=role)

# Example module route
@app.route('/kartlar/stok')
@login_required
@permission_required('Stok Kartları')
def stok_kartlari():
    stocks = Stock.query.all()
    return render_template('stocks.html', stocks=stocks)

@app.route('/kartlar/stok/add', methods=['POST'])
@login_required
@permission_required('Stok Kartları')
def add_stock():
    stock = Stock(
        code=request.form['code'],
        name=request.form['name'],
        quantity=request.form.get('quantity') or 0,
        unit=request.form.get('unit')
    )
    db.session.add(stock)
    db.session.commit()
    return redirect(url_for('stok_kartlari'))

@app.route('/kartlar/stok/edit/<int:stock_id>', methods=['POST'])
@login_required
@permission_required('Stok Kartları')
def edit_stock(stock_id):
    stock = Stock.query.get_or_404(stock_id)
    stock.code = request.form['code']
    stock.name = request.form['name']
    stock.quantity = request.form.get('quantity') or 0
    stock.unit = request.form.get('unit')
    db.session.commit()
    return redirect(url_for('stok_kartlari'))

@app.route('/kartlar/stok/delete/<int:stock_id>')
@login_required
@permission_required('Stok Kartları')
def delete_stock(stock_id):
    stock = Stock.query.get_or_404(stock_id)
    db.session.delete(stock)
    db.session.commit()
    return redirect(url_for('stok_kartlari'))

if __name__ == '__main__':
    if not os.path.exists('stok.db'):
        with app.app_context():
            init_db()
    app.run(debug=True)
