from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask import g
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import re

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///products.db'
db = SQLAlchemy(app)

# Database models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)


class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    image_filename = db.Column(db.String(100), nullable=True)

@app.before_request
def before_request():
    g.user = None
    if 'user_id' in session:
        g.user = User.query.get(session['user_id'])

@app.route('/')
def index():
    products = Product.query.all()
    return render_template('index.html', products=products)

@app.route('/product/<int:product_id>')
def product_detail(product_id):
    product = Product.query.get_or_404(product_id)
    return render_template('product.html', product=product)


@app.route('/cart')
def cart():
    if 'cart' not in session:
        session['cart'] = {}

    cart = session['cart']
    cart_products = []
    total_price = 0

    for product_id, quantity in cart.items():
        product = Product.query.get(int(product_id))  # Product ID'yi integer'a çevir
        if product:
            item_total = product.price * quantity
            total_price += item_total
            cart_products.append({
                'product': product,
                'quantity': quantity,
                'item_total': "{:.2f}".format(item_total)  # İki ondalık basamakla formatla
            })

    total_price = "{:.2f}".format(total_price)  # Toplam fiyatı iki ondalık basamakla formatla

    return render_template('cart.html', cart_products=cart_products, total_price=total_price)




@app.route('/add_to_cart/<int:product_id>')
def add_to_cart(product_id):
    if 'cart' not in session:
        session['cart'] = {}

    cart = session['cart']

    # Ürün ID'sini her zaman integer olarak saklayın ve miktarı artırın
    product_id = str(product_id)  # Product ID'yi string olarak kullanıyoruz (JSON ile uyumlu olması için)
    if product_id in cart:
        cart[product_id] += 1
    else:
        cart[product_id] = 1

    session['cart'] = cart  # Güncellenmiş sepeti oturuma kaydedin
    session.modified = True  # Oturumun değiştiğini belirt

    return redirect(url_for('cart'))



@app.route('/remove_from_cart/<int:product_id>')
def remove_from_cart(product_id):
    if 'cart' in session:
        cart = session['cart']
        product_id = str(product_id)  # Product ID'yi string olarak kullan

        if product_id in cart:
            if cart[product_id] > 1:
                cart[product_id] -= 1
            else:
                del cart[product_id]

        session['cart'] = cart  # Güncellenmiş sepeti oturuma kaydedin
        session.modified = True  # Oturumun değiştiğini belirt

    return redirect(url_for('cart'))




@app.route('/reset_cart')
def reset_cart():
    session.pop('cart', None)  # Mevcut sepeti siler
    session['cart'] = {}  # Yeni bir boş sözlük ile başlatır
    return redirect(url_for('cart'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Şifre geçerlilik kontrolü (en az bir harf içermeli)
        if len(password) < 8:
            flash('Password must be at least 8 characters long.')
            return redirect(request.url)
        if not re.search(r'[A-Za-z]', password):
            flash('Password must contain at least one letter.')
            return redirect(request.url)

        hashed_password = generate_password_hash(password)
        user = User(username=username, password=hashed_password)
        db.session.add(user)
        db.session.commit()

        flash('Registration successful! Please log in.')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        # Kullanıcı adı veya şifre hatalıysa uyarı göster
        if user is None or not check_password_hash(user.password, password):
            flash('Invalid username or password. Please try again.')
            return redirect(url_for('login'))

        # Giriş başarılıysa, kullanıcıyı oturuma ekle
        session['user_id'] = user.id
        return redirect(url_for('index'))

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()

        # Örnek ürünleri sadece bir kez eklemek için kontrol yapın
        if not Product.query.first():
            db.session.add(Product(name="Product 1", price=49.90, image_filename="product1.jpg"))
            db.session.add(Product(name="Product 2", price=69.90, image_filename="product2.jpg"))
            db.session.add(Product(name="Product 3", price=29.90, image_filename="product3.jpg"))
            db.session.commit()

    app.run(debug=True)