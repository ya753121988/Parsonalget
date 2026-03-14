import os
import bcrypt
from flask import Flask, render_template_string, request, redirect, url_for, session, flash, jsonify
from pymongo import MongoClient
from bson.objectid import ObjectId
from functools import wraps
from datetime import datetime

app = Flask(__name__)

# --- CONFIGURATION (Vercel Environment Variables এ সেট করবেন) ---
app.secret_key = os.environ.get("SECRET_KEY", "secure_random_string_8899")
MONGO_URI = os.environ.get("MONGO_URI", "your_mongodb_uri_here")
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "admin123")

# MongoDB Connection
client = MongoClient(MONGO_URI)
db = client['mfs_payment_gateway']
users_col = db['users']
mfs_col = db['mfs_numbers']
payments_col = db['payments']

# --- MFS Configuration (Logos & UI) ---
MFS_INFO = {
    "bKash": {"logo": "https://www.logo.wine/a/logo/BKash-bKash-Logo.wine.svg", "color": "#e2136e"},
    "Nagad": {"logo": "https://www.logo.wine/a/logo/Nagad-Logo.wine.svg", "color": "#f7941d"},
    "Rocket": {"logo": "https://download.logo.wine/logo/Rocket_(mobile_banking_service)/Rocket_(mobile_banking_service)-Logo.wine.png", "color": "#8c3494"},
    "Upay": {"logo": "https://www.upay.com.bd/assets/images/upay-logo.png", "color": "#ffc40c"}
}

# --- DECORATORS & UTILS ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('role') != 'admin':
            return "Unauthorized", 403
        return f(*args, **kwargs)
    return decorated_function

# --- SECURITY SCRIPTS (Right Click & Inspect Block) ---
SECURITY_JS = """
<script>
    document.addEventListener('contextmenu', event => event.preventDefault());
    document.onkeydown = function(e) {
        if(event.keyCode == 123) return false;
        if(e.ctrlKey && e.shiftKey && e.keyCode == 'I'.charCodeAt(0)) return false;
        if(e.ctrlKey && e.keyCode == 'U'.charCodeAt(0)) return false;
    }
    function copyToClipboard(text) {
        navigator.clipboard.writeText(text);
        alert("নম্বর কপি হয়েছে: " + text);
    }
</script>
"""

# --- HTML TEMPLATES ---
LAYOUT = f"""
<!DOCTYPE html>
<html lang="bn">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MFS Gateway</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    {SECURITY_JS}
    <style>
        body {{ background: #f0f2f5; font-family: 'Segoe UI', Tahoma; }}
        .card {{ border-radius: 15px; border: none; box-shadow: 0 4px 12px rgba(0,0,0,0.1); }}
        .btn-primary {{ background: #6c5ce7; border: none; }}
        .mfs-box {{ border: 2px solid #eee; border-radius: 10px; padding: 15px; transition: 0.3s; }}
        .mfs-box:hover {{ border-color: #6c5ce7; }}
    </style>
</head>
<body class="container py-4">
    <nav class="d-flex justify-content-between mb-4">
        <a href="/" class="h4 text-decoration-none text-dark">MFS Gateway</a>
        <div>
            {% if session.get('user_id') %}
                <a href="/dashboard" class="btn btn-sm btn-outline-primary">Dashboard</a>
                {% if session.get('role') == 'admin' %} <a href="/admin" class="btn btn-sm btn-dark">Admin</a> {% endif %}
                <a href="/logout" class="btn btn-sm btn-danger">Logout</a>
            {% else %}
                <a href="/login" class="btn btn-sm btn-primary">Login</a>
                <a href="/register" class="btn btn-sm btn-outline-primary">Register</a>
            {% endif %}
        </div>
    </nav>
    {{% block content %}}{{% endblock %}}
</body>
</html>
"""

# --- ROUTES ---

@app.route('/')
def index():
    return render_template_string(LAYOUT + """
    {% block content %}
    <div class="text-center py-5">
        <h1>Welcome to MFS Secure Gateway</h1>
        <p>সহজে পেমেন্ট গেটওয়ে সেটআপ করুন আপনার সাইটের জন্য।</p>
        <a href="/register" class="btn btn-lg btn-primary">শুরু করুন</a>
    </div>
    {% endblock %}
    """)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        phone = request.form.get('phone')
        password = request.form.get('password')
        if users_col.find_one({"phone": phone}):
            flash("এই নম্বর দিয়ে আগেই অ্যাকাউন্ট খোলা হয়েছে।")
        else:
            hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            users_col.insert_one({"phone": phone, "password": hashed_pw, "role": "user"})
            flash("রেজিস্ট্রেশন সফল! লগইন করুন।")
            return redirect(url_for('login'))
    return render_template_string(LAYOUT + """
    {% block content %}
    <div class="row justify-content-center"><div class="col-md-5 card p-4">
        <h3>Create Account</h3>
        <form method="POST">
            <label>Mobile Number</label>
            <input type="text" name="phone" class="form-control mb-3" placeholder="017XXXXXXXX" required>
            <label>Password</label>
            <input type="password" name="password" class="form-control mb-3" placeholder="******" required>
            <button class="btn btn-primary w-100">Register</button>
        </form>
    </div></div>
    {% endblock %}
    """)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        phone = request.form.get('phone')
        password = request.form.get('password')
        
        # Admin Bypass
        if phone == ADMIN_USER and password == ADMIN_PASS:
            session['user_id'] = 'admin'
            session['role'] = 'admin'
            return redirect(url_for('admin'))

        user = users_col.find_one({"phone": phone})
        if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
            session['user_id'] = str(user['_id'])
            session['role'] = user.get('role', 'user')
            return redirect(url_for('dashboard'))
        flash("ভুল তথ্য দিয়েছেন।")
    return render_template_string(LAYOUT + """
    {% block content %}
    <div class="row justify-content-center"><div class="col-md-5 card p-4">
        <h3>Login</h3>
        <form method="POST">
            <input type="text" name="phone" class="form-control mb-3" placeholder="Phone Number" required>
            <input type="password" name="password" class="form-control mb-3" placeholder="Password" required>
            <button class="btn btn-success w-100">Login</button>
        </form>
        {% with msgs = get_flashed_messages() %} {% if msgs %} <p class="text-danger mt-2">{{msgs[0]}}</p> {% endif %} {% endwith %}
    </div></div>
    {% endblock %}
    """)

@app.route('/dashboard')
@login_required
def dashboard():
    my_payments = list(payments_col.find({"user_id": session['user_id']}).sort("date", -1))
    return render_template_string(LAYOUT + """
    {% block content %}
    <h3>My Dashboard</h3>
    <div class="card p-3 mt-3">
        <h5>Payment History</h5>
        <table class="table table-hover">
            <thead><tr><th>Amount</th><th>TrxID</th><th>Status</th><th>Date</th></tr></thead>
            <tbody>
                {% for p in payments %}
                <tr>
                    <td>{{p.amount}} TK</td><td>{{p.trxid}}</td>
                    <td><span class="badge {% if p.status=='Pending' %}bg-warning{% else %}bg-success{% endif %}">{{p.status}}</span></td>
                    <td>{{p.date.strftime('%d-%m-%Y')}}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
    {% endblock %}
    """, payments=my_payments)

# --- GATEWAY PAGE (অন্য সাইটে iframe দিয়ে দেখানোর জন্য) ---
@app.route('/pay')
def pay():
    amount = request.args.get('amount', '0')
    mfs_nums = list(mfs_col.find())
    return render_template_string(LAYOUT + """
    {% block content %}
    <div class="card p-4 mx-auto" style="max-width: 600px;">
        <h4 class="text-center">নিচের নাম্বারে টাকা পাঠিয়ে TrxID দিন</h4>
        <h2 class="text-center text-primary mb-4">{{amount}} TK</h2>
        <div class="row g-2">
            {% for n in numbers %}
            <div class="col-6">
                <div class="mfs-box text-center">
                    <img src="{{mfs_info[n.provider].logo}}" height="30">
                    <div class="fw-bold mt-2">{{n.number}}</div>
                    <small class="text-muted">{{n.type}}</small><br>
                    <button class="btn btn-sm btn-light mt-1" onclick="copyToClipboard('{{n.number}}')">Copy</button>
                </div>
            </div>
            {% endfor %}
        </div>
        <form action="/submit-payment" method="POST" class="mt-4">
            <input type="hidden" name="amount" value="{{amount}}">
            <input type="text" name="trxid" class="form-control mb-2" placeholder="ট্রানজেকশন আইডি দিন" required>
            <button class="btn btn-primary w-100">পেমেন্ট নিশ্চিত করুন</button>
        </form>
    </div>
    {% endblock %}
    """, amount=amount, numbers=mfs_nums, mfs_info=MFS_INFO)

@app.route('/submit-payment', methods=['POST'])
def submit_payment():
    payments_col.insert_one({
        "user_id": session.get('user_id', 'Guest'),
        "amount": request.form.get('amount'),
        "trxid": request.form.get('trxid'),
        "status": "Pending",
        "date": datetime.now()
    })
    return "<h1>ধন্যবাদ! আপনার পেমেন্টটি রিভিউ করা হচ্ছে।</h1><a href='/dashboard'>ড্যাশবোর্ড দেখুন</a>"

# --- ADMIN PANEL ---
@app.route('/admin')
@login_required
@admin_required
def admin():
    nums = list(mfs_col.find())
    pays = list(payments_col.find().sort("date", -1))
    return render_template_string(LAYOUT + """
    {% block content %}
    <h2>Admin Control Panel</h2>
    <div class="row mt-4">
        <div class="col-md-4">
            <div class="card p-3 mb-3">
                <h5>Add Number</h5>
                <form action="/admin/add-num" method="POST">
                    <select name="provider" class="form-select mb-2">
                        <option value="bKash">bKash</option><option value="Nagad">Nagad</option>
                        <option value="Rocket">Rocket</option><option value="Upay">Upay</option>
                    </select>
                    <input type="text" name="number" class="form-control mb-2" placeholder="Number" required>
                    <select name="type" class="form-select mb-2">
                        <option value="Personal">Personal</option><option value="Agent">Agent</option>
                    </select>
                    <button class="btn btn-sm btn-success w-100">Add Number</button>
                </form>
            </div>
            <div class="card p-3">
                <h5>Existing Numbers</h5>
                <ul class="list-group">
                    {% for n in nums %}
                    <li class="list-group-item d-flex justify-content-between">
                        {{n.provider}}: {{n.number}}
                        <a href="/admin/del-num/{{n._id}}" class="text-danger">Del</a>
                    </li>
                    {% endfor %}
                </ul>
            </div>
        </div>
        <div class="col-md-8">
            <div class="card p-3">
                <h5>Recent Transactions</h5>
                <table class="table table-sm">
                    <thead><tr><th>TrxID</th><th>Amount</th><th>Status</th><th>Action</th></tr></thead>
                    <tbody>
                        {% for p in pays %}
                        <tr>
                            <td>{{p.trxid}}</td><td>{{p.amount}}</td>
                            <td>{{p.status}}</td>
                            <td>
                                {% if p.status == 'Pending' %}
                                <a href="/admin/approve/{{p._id}}" class="btn btn-xs btn-primary">Approve</a>
                                {% endif %}
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    {% endblock %}
    """, nums=nums, pays=pays)

@app.route('/admin/add-num', methods=['POST'])
@login_required
@admin_required
def add_num():
    mfs_col.insert_one({
        "provider": request.form.get('provider'),
        "number": request.form.get('number'),
        "type": request.form.get('type')
    })
    return redirect(url_for('admin'))

@app.route('/admin/del-num/<id>')
@login_required
@admin_required
def del_num(id):
    mfs_col.delete_one({"_id": ObjectId(id)})
    return redirect(url_for('admin'))

@app.route('/admin/approve/<id>')
@login_required
@admin_required
def approve(id):
    payments_col.update_one({"_id": ObjectId(id)}, {"$set": {"status": "Completed"}})
    return redirect(url_for('admin'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
