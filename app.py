import os
import math
import requests
import re
import stripe 
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
from authlib.integrations.flask_client import OAuth
from flask_mail import Mail, Message
from dotenv import load_dotenv
import PyPDF2
import docx
from flask_socketio import SocketIO, emit, join_room, leave_room

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default-key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


# Initialize SocketIO
socketio = SocketIO(app, cors_allowed_origins="*")

# --- STRIPE CONFIGURATION ---
stripe.api_key = os.getenv('STRIPE_SECRET_KEY')
app.config['STRIPE_PUBLISHABLE_KEY'] = os.getenv('STRIPE_PUBLISHABLE_KEY')
app.config['STRIPE_PRICE_BASIC'] = os.getenv('STRIPE_PRICE_BASIC')
app.config['STRIPE_PRICE_PRO'] = os.getenv('STRIPE_PRICE_PRO')
app.config['STRIPE_WEBHOOK_SECRET'] = os.getenv('STRIPE_WEBHOOK_SECRET')

# --- FOLDERS ---
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['CERT_FOLDER'] = 'static/certs'
app.config['RESUME_FOLDER'] = 'static/resumes'
app.config['PROFILE_PIC_FOLDER'] = 'static/profile_pics'
app.config['EXP_PROOF_FOLDER'] = 'static/experience_proofs'
app.config['ID_PROOF_FOLDER'] = 'static/id_proofs'
app.config['TEMP_FOLDER'] = 'static/temp_docs'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024

folders = [
    app.config['UPLOAD_FOLDER'],
    app.config['CERT_FOLDER'], app.config['RESUME_FOLDER'],
    app.config['PROFILE_PIC_FOLDER'], app.config['EXP_PROOF_FOLDER'],
    app.config['ID_PROOF_FOLDER'], app.config['TEMP_FOLDER']
]
for folder in folders:
    os.makedirs(folder, exist_ok=True)

# --- CONFIG ---
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
mail = Mail(app)

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
app.config['GOOGLE_CLIENT_ID'] = os.getenv('GOOGLE_CLIENT_ID')
app.config['GOOGLE_CLIENT_SECRET'] = os.getenv('GOOGLE_CLIENT_SECRET')
app.config['GOOGLE_DISCOVERY_URL'] = "https://accounts.google.com/.well-known/openid-configuration"

oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    server_metadata_url=app.config['GOOGLE_DISCOVERY_URL'],
    client_kwargs={'scope': 'openid email profile'},
)
db = SQLAlchemy()
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# --- MODELS ---
class User(UserMixin, db.Model):
    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)

    # 🔴 IMPORTANT: password hashes are LONG
    # Werkzeug hashes can exceed 300 chars
    password = db.Column(db.Text, nullable=True)

    role = db.Column(db.String(50), default='coach')

    # Google IDs & profile pics can also be long
    google_id = db.Column(db.String(255), unique=True)
    profile_pic = db.Column(db.Text)

    # STRIPE FIELDS
    subscription_status = db.Column(db.String(50), default='free')  # free, basic, pro
    stripe_customer_id = db.Column(db.String(255))

    # Relationships
    profile = db.relationship('Profile', backref='user', uselist=False, cascade="all, delete-orphan")
    jobs = db.relationship('Job', backref='employer', lazy=True)
    applications = db.relationship('Application', backref='applicant', lazy=True)
    reviews_given = db.relationship('Review', backref='reviewer', lazy=True)

class Profile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    full_name = db.Column(db.String(150))
    phone = db.Column(db.String(20))
    sport = db.Column(db.String(100))
    experience_years = db.Column(db.Integer)
    certifications = db.Column(db.String(500))
    bio = db.Column(db.Text)
    city = db.Column(db.String(100))
    travel_range = db.Column(db.String(100))
    is_verified = db.Column(db.Boolean, default=False)
    views = db.Column(db.Integer, default=0)
    
    cert_proof_path = db.Column(db.String(300))
    resume_path = db.Column(db.String(300))
    experience_proof_path = db.Column(db.String(300))
    id_proof_path = db.Column(db.String(300))
    reviews = db.relationship('Review', backref='profile', lazy=True)

class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    profile_id = db.Column(db.Integer, db.ForeignKey('profile.id'), nullable=False)
    reviewer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.Text)
    date = db.Column(db.DateTime, default=datetime.utcnow)

class Job(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    employer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(150), nullable=False)
    sport = db.Column(db.String(100), nullable=False)
    location = db.Column(db.String(150), nullable=False)
    lat = db.Column(db.Float, nullable=True)
    lng = db.Column(db.Float, nullable=True)
    description = db.Column(db.Text, nullable=False)
    requirements = db.Column(db.Text)
    screening_questions = db.Column(db.Text)
    is_active = db.Column(db.Boolean, default=True)
    salary_range = db.Column(db.String(100))
    posted_date = db.Column(db.DateTime, default=datetime.utcnow)
    required_skills = db.Column(db.String(300))
    job_type = db.Column(db.String(50), default='Full Time')  
    working_hours = db.Column(db.String(100)) 

class Application(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.Integer, db.ForeignKey('job.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(50), default='Applied')
    match_score = db.Column(db.Integer)
    # NEW: Store the 'Why' behind the score
    match_reasons = db.Column(db.Text) 
    applied_date = db.Column(db.DateTime, default=datetime.utcnow)
    custom_resume_path = db.Column(db.String(300))
    screening_answers = db.Column(db.Text)
    job = db.relationship('Job', backref='applications')

# --- CHAT MODEL ---
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)

    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_messages')
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref='received_messages')

# --- HELPERS ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def get_profile_completion(profile):
    if not profile:
        return 0
    score = 0
    if profile.full_name: score += 10
    if profile.user.profile_pic: score += 10
    if profile.sport: score += 10
    if profile.experience_years: score += 10
    if profile.experience_proof_path: score += 10
    if profile.bio: score += 10
    if profile.phone: score += 10
    if profile.certifications: score += 10
    if profile.id_proof_path: score += 10
    if profile.resume_path: score += 10
    return min(score, 100)

@app.context_processor
def inject_globals():
    completion = 0
    if current_user.is_authenticated and current_user.role == 'coach':
        completion = get_profile_completion(current_user.profile)
    return dict(profile_completion=completion)

def send_notification_email(recipient_email, subject, body):
    if not app.config['MAIL_USERNAME'] or not app.config['MAIL_PASSWORD']:
        return
    try:
        msg = Message(subject, sender=app.config['MAIL_USERNAME'], recipients=[recipient_email])
        msg.body = body
        mail.send(msg)
    except Exception as e:
        print(f"Email failed: {e}")

def haversine(lat1, lon1, lat2, lon2):
    lon1, lat1, lon2, lat2 = map(math.radians, [lon1, lat1, lon2, lat2])
    a = math.sin((lat2-lat1)/2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin((lon2-lon1)/2)**2
    c = 2 * math.asin(math.sqrt(a))
    return c * 6371

# ----------------------------------------------------
# UPDATED AI EXPLAINABILITY LOGIC
# ----------------------------------------------------
def calculate_ai_score(job, profile):
    score = 0
    reasons = [] # List to track the "Why"

    if not profile:
        return 0, "Profile incomplete"

    # 1. Sport Match (+40)
    if job.sport.lower() in profile.sport.lower():
        score += 40
        reasons.append("Sport Match (+40)")

    # 2. Experience Level (+30)
    if profile.experience_years and profile.experience_years >= 2:
        score += 30
        reasons.append(f"Experience > 2y (+30)")
    
    # 3. Trust Factor (+20)
    if profile.is_verified:
        score += 20
        reasons.append("Verified Badge (+20)")

    # 4. Certification Keyword Matching (+10)
    if job.requirements and profile.certifications:
        # Normalize and split into sets of words
        job_keywords = set(job.requirements.lower().replace(',', '').split())
        cert_keywords = set(profile.certifications.lower().replace(',', '').split())
        
        # Check intersection
        common_words = job_keywords.intersection(cert_keywords)
        if common_words:
            score += 10
            matched_terms = list(common_words)[:2] # Take first 2 matched words
            reasons.append(f"Cert Match: {', '.join(matched_terms)} (+10)")

    # Return Tuple: (Score, Reasons String)
    return min(score, 100), " | ".join(reasons)

def predict_salary_ai(sport, location, description, job_type):
    base = 15000
    reason = "Base entry level."

    if sport and sport.lower() == 'cricket':
        base += 10000
        reason = "Cricket (High Demand)"
    elif sport and sport.lower() == 'football':
        base += 5000
        reason = "Football (Growing Demand)"

    if location and ('mumbai' in location.lower() or 'delhi' in location.lower() or 'bangalore' in location.lower()):
        base += 8000
        reason += " + Metro City"

    desc_lower = description.lower() if description else ""
    if 'head coach' in desc_lower or 'senior' in desc_lower:
        base += 15000
        reason += " + Senior Role"

    if job_type == 'Internship':
        base = base * 0.4
        reason += " (Adjusted for Internship)"
    elif job_type == 'Part Time':
        base = base * 0.6
        reason += " (Pro-rated for Part Time)"
    elif job_type == 'Contract':
        base = base * 1.2
        reason += " (Contract Premium)"

    min_sal = int(base)
    max_sal = int(base * 1.2)

    return (f"{min_sal} - {max_sal}", reason)

def smart_parse_document(filepath):
    text = ""
    ext = filepath.rsplit('.', 1)[1].lower()
    try:
        if ext == 'pdf':
            with open(filepath, 'rb') as f:
                reader = PyPDF2.PdfReader(f)
                for page in reader.pages:
                    text += page.extract_text() + "\n"
        elif ext == 'docx':
            doc = docx.Document(filepath)
            for para in doc.paragraphs:
                text += para.text + "\n"
        elif ext == 'txt':
            with open(filepath, 'r', encoding='utf-8') as f:
                text = f.read()
    except Exception as e:
        print(f"Parsing error: {e}")
        return {}

    lines = [line.strip() for line in text.split('\n') if line.strip()]
    data = {'description': '', 'requirements': '', 'title': '', 'location': '', 'sport': '', 'salary': ''}

    current_section = 'description'
    desc_lines = []
    req_lines = []
    expect_next = None

    for line in lines:
        lower_line = line.lower()
        if lower_line.startswith('job title:') or lower_line.startswith('title:') or lower_line.startswith('role:'):
            parts = line.split(':', 1)
            if len(parts) > 1 and parts[1].strip():
                data['title'] = parts[1].strip()
            continue

        if lower_line.strip() == 'job title' or lower_line.strip() == 'role':
            expect_next = 'title'
            continue
        if expect_next == 'title':
            data['title'] = line
            expect_next = None
            continue

        if lower_line.startswith('location:') or lower_line.startswith('venue:'):
            data['location'] = line.split(':', 1)[1].strip()
            continue
        if lower_line.startswith('salary:') or lower_line.startswith('pay:'):
            data['salary'] = line.split(':', 1)[1].strip()
            continue

        if 'requirements:' in lower_line or 'qualifications:' in lower_line:
            current_section = 'requirements'
            continue
        elif 'responsibilities:' in lower_line or 'job description:' in lower_line:
            current_section = 'description'
            desc_lines.append(line)
            continue

        if current_section == 'requirements':
            req_lines.append(line)
        else:
            desc_lines.append(line)

    full_text_lower = text.lower()
    sports_list = ['Cricket', 'Football', 'Tennis', 'Basketball', 'Badminton', 'Swimming', 'Hockey', 'Athletics']

    for s in sports_list:
        if s.lower() in full_text_lower:
            data['sport'] = s
            break

    if not data['location']:
        cities = ['Mumbai', 'Delhi', 'Bangalore', 'Gurugram', 'Pune', 'Hyderabad', 'Chennai', 'Kolkata', 'Ahmedabad']
        for c in cities:
            if c.lower() in full_text_lower:
                data['location'] = c
                break

    if not data['title'] and lines:
        first_line = lines[0]
        if "coach" in first_line.lower() or "trainer" in first_line.lower():
            data['title'] = first_line

    data['description'] = "\n".join(desc_lines).strip()
    data['requirements'] = "\n".join(req_lines).strip()
    return data

def generate_ai_resume_content(profile):
    if not profile:
        return "No profile data."
    summary = f"Passionate and results-driven {profile.sport} Coach with over {profile.experience_years} years of experience. Expert in {profile.sport} techniques."
    return summary

# --- ROUTES ---

@app.route('/coaches')
@login_required
def explore_coaches():
    sport = request.args.get('sport', type=str)
    verified = request.args.get('verified')      
    min_exp = request.args.get('min_exp', type=int)
    page = request.args.get('page', 1, type=int)
    per_page = 12

    query = Profile.query.join(Profile.user)
    query = query.filter(User.role == 'coach')

    if sport:
        query = query.filter(Profile.sport.ilike(f"%{sport}%"))
    if verified == '1':
        query = query.filter(Profile.is_verified == True)
    if min_exp is not None:
        query = query.filter(Profile.experience_years >= min_exp)

    query = query.order_by(Profile.is_verified.desc(), Profile.experience_years.desc(), Profile.id.desc())

    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    coaches = pagination.items

    user_lat = request.args.get('lat', type=float)
    user_lng = request.args.get('lng', type=float)
    if user_lat is not None and user_lng is not None:
        for p in coaches:
            lat_attr = getattr(p, 'lat', None)
            lng_attr = getattr(p, 'lng', None)
            if lat_attr and lng_attr:
                p.distance_km = round(haversine(user_lat, user_lng, lng_attr, lat_attr), 1)
            else:
                p.distance_km = None

    sports_rows = db.session.query(Profile.sport).filter(Profile.sport != None).distinct().all()
    sports = [s[0] for s in sports_rows if s[0]]

    return render_template('coach_explore.html',
                           coaches=coaches,
                           pagination=pagination,
                           sports=sports,
                           filters=dict(sport=sport, verified=verified, min_exp=min_exp, lat=user_lat, lng=user_lng))


@app.route('/plans')
@login_required
def show_plans():
    return render_template('plans.html')

@app.route('/job/new', methods=['GET', 'POST'])
@login_required
def new_job():
    if current_user.role != 'employer':
        return redirect(url_for('dashboard'))
    
    # STRIPE CHECK: Ensure paid plan for jobs (Optional logic)
    # if current_user.subscription_status == 'free':
    #     flash("Please upgrade to post jobs.")
    #     return redirect(url_for('show_plans'))
    
    predicted_salary = None
    ai_reason = None
    form_data = {}

    if request.method == 'POST':
        if 'parse_doc' in request.form:
            f = request.files.get('job_doc')
            if f and f.filename != '':
                filename = secure_filename(f"temp_{current_user.id}_{f.filename}")
                filepath = os.path.join(app.config['TEMP_FOLDER'], filename)
                f.save(filepath)
                extracted = smart_parse_document(filepath)
                form_data = extracted
                flash("✨ Document Parsed! We filled the details for you.")
                try:
                    os.remove(filepath)
                except:
                    pass
                return render_template('job_new.html', form_data=form_data)

        if 'predict' in request.form:
            sport = request.form.get('sport')
            location = request.form.get('location')
            description = request.form.get('description')
            job_type = request.form.get('job_type')

            predicted_salary, ai_reason = predict_salary_ai(sport, location, description, job_type)
            flash(f"AI Suggested Salary: ₹{predicted_salary}/month")

            form_data = {
                'title': request.form.get('title'),
                'sport': request.form.get('sport'),
                'location': request.form.get('location'),
                'description': request.form.get('description'),
                'requirements': request.form.get('requirements'),
                'screening_questions': request.form.get('screening_questions'),
                'salary': request.form.get('salary'),
                'lat': request.form.get('lat'),
                'lng': request.form.get('lng'),
                'job_type': request.form.get('job_type'),
                'working_hours': request.form.get('working_hours')
            }
            return render_template('job_new.html', predicted_salary=predicted_salary, ai_reason=ai_reason, form_data=form_data)

        lat = request.form.get('lat')
        lng = request.form.get('lng')
        new_job = Job(
            employer_id=current_user.id,
            title=request.form.get('title'),
            sport=request.form.get('sport'),
            location=request.form.get('location'),
            lat=float(lat) if lat and lat.strip() != '' else None,
            lng=float(lng) if lng and lng.strip() != '' else None,
            description=request.form.get('description'),
            requirements=request.form.get('requirements'),
            screening_questions=request.form.get('screening_questions'),
            salary_range=request.form.get('salary'),
            job_type=request.form.get('job_type'),
            working_hours=request.form.get('working_hours'),
            is_active=True
        )
        db.session.add(new_job)
        db.session.commit()
        return redirect(url_for('dashboard'))

    return render_template('job_new.html')

@app.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if current_user.role != 'coach':
        return redirect(url_for('dashboard'))
    profile = Profile.query.filter_by(user_id=current_user.id).first()
    if request.method == 'POST':
        profile.full_name = request.form.get('full_name')
        profile.phone = request.form.get('phone')
        profile.sport = request.form.get('sport')
        profile.city = request.form.get('city')
        profile.travel_range = request.form.get('travel_range')
        profile.experience_years = int(request.form.get('experience_years') or 0)
        profile.certifications = request.form.get('certifications')
        profile.bio = request.form.get('bio')

        files_map = {
            'profile_image': (app.config['PROFILE_PIC_FOLDER'], 'pic_', 'current_user'),
            'cert_proof': (app.config['CERT_FOLDER'], 'cert_', 'profile'),
            'resume_pdf': (app.config['RESUME_FOLDER'], 'resume_', 'profile'),
            'experience_proof': (app.config['EXP_PROOF_FOLDER'], 'exp_', 'profile'),
            'id_proof': (app.config['ID_PROOF_FOLDER'], 'id_', 'profile')
        }
        for key, (folder, prefix, target) in files_map.items():
            f = request.files.get(key)
            if f and f.filename != '':
                filename = secure_filename(f"{prefix}{current_user.id}_{f.filename}")
                f.save(os.path.join(folder, filename))
                if key == 'profile_image':
                    current_user.profile_pic = url_for('static', filename=f'profile_pics/{filename}')
                elif key == 'id_proof':
                    profile.id_proof_path = filename
                elif key == 'cert_proof':
                    profile.cert_proof_path = filename
                elif key == 'resume_pdf':
                    profile.resume_path = filename
                elif key == 'experience_proof':
                    profile.experience_proof_path = filename
        db.session.commit()
        flash('Profile Updated Successfully!')
        return redirect(url_for('dashboard'))
    return render_template('coach_profile.html', profile=profile)

@app.route('/login/google')
def login_google():
    redirect_uri = url_for('authorize_google', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/authorize/google')
def authorize_google():
    try:
        token = google.authorize_access_token()
        user_info = google.parse_id_token(token, nonce=None)
        user = User.query.filter_by(email=user_info['email']).first()
        if user:
            login_user(user)
            if user.role == 'employer':
                return redirect(url_for('show_plans'))
            if user.role == 'coach':
                return redirect(url_for('show_plans'))
            return redirect(url_for('dashboard'))
        else:
            session['google_user'] = user_info
            return redirect(url_for('select_role'))
    except Exception as e:
        flash(f"Google Login Failed: {str(e)}")
        return redirect(url_for('login'))

@app.route('/select-role', methods=['GET', 'POST'])
def select_role():
    if 'google_user' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        role = request.form.get('role')
        user_info = session['google_user']
        user = User(username=user_info['name'], email=user_info['email'], google_id=user_info['sub'], profile_pic=user_info['picture'], role=role)
        db.session.add(user)
        db.session.commit()
        if role == 'coach':
            db.session.add(Profile(user_id=user.id, full_name=user_info['name']))
            db.session.commit()
        login_user(user)
        session.pop('google_user', None)
        if user.role == 'employer':
            return redirect(url_for('show_plans'))
        if user.role == 'coach':
            return redirect(url_for('show_plans'))
        return redirect(url_for('dashboard'))
    return render_template('select_role.html')

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if User.query.filter_by(email=request.form.get('email')).first():
            flash('Email already exists')
            return redirect(url_for('register'))
        new_user = User(username=request.form.get('username'), email=request.form.get('email'),
                        role=request.form.get('role'), password=generate_password_hash(request.form.get('password')))
        db.session.add(new_user)
        db.session.commit()
        if new_user.role == 'coach':
            db.session.add(Profile(user_id=new_user.id))
            db.session.commit()
        login_user(new_user)
        if new_user.role == 'employer':
            return redirect(url_for('show_plans'))
        if new_user.role == 'coach':
            return redirect(url_for('show_plans'))
        return redirect(url_for('dashboard'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form.get('email')).first()
        if user and user.password and check_password_hash(user.password, request.form.get('password')):
            login_user(user)
            if user.role == 'admin':
                return redirect(url_for('super_admin'))
            if user.role == 'employer':
                return redirect(url_for('show_plans'))
            if user.role == 'coach':
                return redirect(url_for('show_plans'))
            return redirect(url_for('dashboard'))
        elif user and not user.password:
            flash('This account was created with Google. Please use "Login with Google".')
        else:
            flash('Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin':
        return redirect(url_for('super_admin'))
    if current_user.role == 'employer':
        my_jobs = Job.query.filter_by(employer_id=current_user.id).order_by(Job.is_active.desc(), Job.posted_date.desc()).all()
        applications = []
        for job in my_jobs:
            applications.extend(job.applications)
        return render_template('admin_dashboard.html', jobs=my_jobs, applications=applications, total_applicants=len(applications))
    else:
        views = current_user.profile.views
        query = Job.query.filter_by(is_active=True)
        if request.args.get('sport') and request.args.get('sport') != 'All':
            query = query.filter_by(sport=request.args.get('sport'))
        all_jobs = query.all()
        filtered_jobs = []
        user_lat, user_lng, radius = request.args.get('lat', type=float), request.args.get('lng', type=float), request.args.get('radius', type=float)
        if user_lat and user_lng and radius:
            for job in all_jobs:
                if job.lat and job.lng:
                    dist = haversine(user_lat, user_lng, job.lat, job.lng)
                    if dist <= radius:
                        job.distance = round(dist, 1)
                        filtered_jobs.append(job)
        else:
            filtered_jobs = all_jobs
        my_apps = Application.query.filter_by(user_id=current_user.id).all()
        avg_rating = 0
        if current_user.profile.reviews:
            total = sum([r.rating for r in current_user.profile.reviews])
            avg_rating = round(total / len(current_user.profile.reviews), 1)
        return render_template('coach_listing.html', jobs=filtered_jobs, my_apps=my_apps, views=views, avg_rating=avg_rating)

@app.route('/job/toggle-status/<int:job_id>')
@login_required
def toggle_job_status(job_id):
    if current_user.role != 'employer':
        return redirect(url_for('dashboard'))
    job = Job.query.get_or_404(job_id)
    if job.employer_id != current_user.id:
        flash("Unauthorized")
        return redirect(url_for('dashboard'))
    job.is_active = not job.is_active
    db.session.commit()
    return redirect(url_for('dashboard'))

# ----------------------------------------------------
# UPDATED APPLY JOB ROUTE - SAVING AI REASONS
# ----------------------------------------------------
@app.route('/job/apply/<int:job_id>', methods=['POST'])
@login_required
def apply_job(job_id):
    if current_user.role != 'coach':
        return redirect(url_for('dashboard'))
    if Application.query.filter_by(job_id=job_id, user_id=current_user.id).first():
        flash("Already applied.")
        return redirect(url_for('dashboard'))
    
    job = Job.query.get_or_404(job_id)
    profile = Profile.query.filter_by(user_id=current_user.id).first()
    
    if get_profile_completion(profile) < 50:
        flash("Your profile is incomplete!")
        return redirect(url_for('dashboard'))
    
    resume_path = None
    file = request.files.get('custom_resume')
    if file and file.filename != '':
        filename = secure_filename(f"resume_{current_user.id}_{job_id}_{file.filename}")
        file.save(os.path.join(app.config['RESUME_FOLDER'], filename))
        resume_path = filename
    
    answers_list = []
    if job.screening_questions:
        qs = job.screening_questions.split('|')
        for i in range(len(qs)):
            ans = request.form.get(f'answer_{i}')
            answers_list.append(ans if ans else "No Answer")
    final_answers_str = "|".join(answers_list) if answers_list else None
    
    # UNPACK SCORE AND REASONS
    score, match_reasons = calculate_ai_score(job, profile)
    
    new_app = Application(
        job_id=job_id,
        user_id=current_user.id,
        match_score=score,
        match_reasons=match_reasons, # SAVE REASONS TO DB
        custom_resume_path=resume_path,
        screening_answers=final_answers_str
    )
    db.session.add(new_app)
    db.session.commit()
    
    flash(f"Applied! Match: {score}%")
    return redirect(url_for('dashboard'))

@app.route('/application/status/<int:app_id>/<string:new_status>', methods=['GET', 'POST'])
@login_required
def update_status(app_id, new_status):
    if current_user.role != 'employer':
        return redirect(url_for('dashboard'))
    app_obj = Application.query.get_or_404(app_id)
    if app_obj.job.employer_id != current_user.id:
        flash("Unauthorized")
        return redirect(url_for('dashboard'))
    app_obj.status = new_status
    db.session.commit()
    app_obj.applicant.profile.views += 1
    db.session.commit()
    meeting_link = ""
    if new_status == 'Interview' and request.method == 'POST':
        meeting_link = request.form.get('meeting_link', '')
    subject = f"Update on your application for {app_obj.job.title}"
    body = f"Hello {app_obj.applicant.username},\n\nStatus: {new_status}."
    if meeting_link:
        body += f"\nLink: {meeting_link}"
    send_notification_email(app_obj.applicant.email, subject, body)
    flash(f"Status updated to {new_status}")
    return redirect(url_for('dashboard'))

@app.route('/submit-review/<int:profile_id>', methods=['POST'])
@login_required
def submit_review(profile_id):
    if current_user.role != 'employer':
        return redirect(url_for('dashboard'))
    rating = int(request.form.get('rating'))
    comment = request.form.get('comment')
    new_review = Review(profile_id=profile_id, reviewer_id=current_user.id, rating=rating, comment=comment)
    db.session.add(new_review)
    db.session.commit()
    flash("Review submitted!")
    return redirect(url_for('dashboard'))

@app.route('/super-admin')
@login_required
def super_admin():
    if current_user.role != 'admin':
        flash("Unauthorized")
        return redirect(url_for('dashboard'))
    coaches = Profile.query.filter(Profile.cert_proof_path != None, Profile.is_verified == False).all()
    return render_template('super_admin.html', coaches=coaches)

@app.route('/verify-coach/<int:profile_id>')
@login_required
def verify_coach(profile_id):
    if current_user.role != 'admin':
        return redirect(url_for('dashboard'))
    profile = Profile.query.get_or_404(profile_id)
    profile.is_verified = True
    db.session.commit()
    return redirect(url_for('super_admin'))

@app.route('/reject-coach/<int:profile_id>')
@login_required
def reject_coach(profile_id):
    if current_user.role != 'admin':
        return redirect(url_for('dashboard'))
    profile = Profile.query.get_or_404(profile_id)
    profile.cert_proof_path = None
    db.session.commit()
    return redirect(url_for('super_admin'))

@app.route('/coach/resume/<int:user_id>')
@login_required
def view_resume(user_id):
    if current_user.role != 'employer':
        return redirect(url_for('dashboard'))
    profile = Profile.query.filter_by(user_id=user_id).first_or_404()
    return render_template('resume_print.html', profile=profile)

@app.route('/tools/resume-builder')
@login_required
def resume_builder():
    if current_user.role != 'coach':
        return redirect(url_for('dashboard'))
    ai_summary = generate_ai_resume_content(current_user.profile)
    return render_template('resume_builder.html', profile=current_user.profile, ai_summary=ai_summary)

@app.route('/profile/delete', methods=['POST'])
@login_required
def delete_profile():
    user = User.query.get(current_user.id)
    if user.profile:
        Review.query.filter_by(profile_id=user.profile.id).delete()
        Application.query.filter_by(user_id=user.id).delete()
        db.session.delete(user.profile)
    if user.role == 'employer':
        Job.query.filter_by(employer_id=user.id).delete()
    db.session.delete(user)
    db.session.commit()
    logout_user()
    flash('Your account has been permanently deleted.')
    return redirect(url_for('home'))

@app.route('/job/edit/<int:job_id>', methods=['GET', 'POST'])
@login_required
def edit_job(job_id):
    if current_user.role != 'employer':
        return redirect(url_for('dashboard'))
    job = Job.query.get_or_404(job_id)
    if job.employer_id != current_user.id:
        flash("Unauthorized access!")
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        job.title = request.form.get('title')
        job.sport = request.form.get('sport')
        job.location = request.form.get('location')
        job.description = request.form.get('description')
        job.requirements = request.form.get('requirements')
        job.screening_questions = request.form.get('screening_questions')
        job.salary_range = request.form.get('salary')
        job.job_type = request.form.get('job_type')
        job.working_hours = request.form.get('working_hours')

        lat = request.form.get('lat')
        lng = request.form.get('lng')
        if lat and lng and lat.strip() != '' and lng.strip() != '':
            job.lat = float(lat)
            job.lng = float(lng)

        db.session.commit()
        flash("Job Updated Successfully!")
        return redirect(url_for('dashboard'))

    return render_template('job_edit.html', job=job)

# --- FORGOT PASSWORD ROUTES ---
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            flash(f"Password reset link sent to {email}. Please check your inbox.")
            return redirect(url_for('login'))
        else:
            flash("Email not found.")
    return render_template('forgot_password.html')

@app.route('/reset-password-mock', methods=['GET', 'POST'])
def reset_password_mock():
    if request.method == 'POST':
        flash("Your password has been reset! Please login.")
        return redirect(url_for('login'))
    return render_template('reset_password.html')

# ==============================
#      CHAT ROUTES (UPDATED)
# ==============================
@app.route('/chat')
@app.route('/chat/<int:receiver_id>')
@login_required
def chat(receiver_id=None):
    # Build contacts list based on role
    if current_user.role == 'employer':
        my_jobs = Job.query.filter_by(employer_id=current_user.id).all()
        job_ids = [j.id for j in my_jobs]
        apps = Application.query.filter(Application.job_id.in_(job_ids)).all()
        contacts = list({app.applicant for app in apps})  # distinct applicants
    else:
        my_apps = Application.query.filter_by(user_id=current_user.id).all()
        contacts = list({app.job.employer for app in my_apps})  # distinct employers

    # Enrich contacts with sidebar info
    for u in contacts:
        # last message in this conversation
        last_msg = Message.query.filter(
            ((Message.sender_id == current_user.id) & (Message.receiver_id == u.id)) |
            ((Message.sender_id == u.id) & (Message.receiver_id == current_user.id))
        ).order_by(Message.timestamp.desc()).first()
        u.last_message = last_msg.content if last_msg else None
        u.last_message_time = last_msg.timestamp.isoformat() if last_msg else None
        # unread count: messages from them -> me, not read
        u.unread_count = Message.query.filter_by(sender_id=u.id, receiver_id=current_user.id, is_read=False).count()

    active_contact = None
    messages = []
    room = None

    if receiver_id:
        active_contact = User.query.get_or_404(receiver_id)
        user_ids = sorted([current_user.id, receiver_id])
        room = f"chat_{user_ids[0]}_{user_ids[1]}"

        # conversation messages
        messages = Message.query.filter(
            ((Message.sender_id == current_user.id) & (Message.receiver_id == receiver_id)) |
            ((Message.sender_id == receiver_id) & (Message.receiver_id == current_user.id))
        ).order_by(Message.timestamp.asc()).all()

        # mark their messages to me as read
        changed = False
        for m in messages:
            if m.receiver_id == current_user.id and not m.is_read:
                m.is_read = True
                changed = True
        if changed:
            db.session.commit()

    return render_template('chat.html',
                           contacts=contacts,
                           active_contact=active_contact,
                           messages=messages,
                           room=room)
# =========================================
#             STRIPE WEBHOOK
# =========================================
@app.route('/stripe/webhook', methods=['POST'])
def stripe_webhook():
    payload = request.data
    sig_header = request.headers.get('stripe-signature')
    endpoint_secret = app.config['STRIPE_WEBHOOK_SECRET']

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, endpoint_secret)

    except Exception:
        return "Invalid signature", 400

    # Payment succeeded → activate user
    if event['type'] == 'checkout.session.completed':
        data = event['data']['object']
        user = User.query.filter_by(email=data['customer_email']).first()
        if user:
            user.subscription_status = 'active'
            user.stripe_customer_id = data.get('customer')
            db.session.commit()

    # Subscription expired/cancelled
    if event['type'] in ['customer.subscription.deleted', 'invoice.payment_failed']:
        sub = event['data']['object']
        user = User.query.filter_by(stripe_customer_id=sub.get('customer')).first()
        if user:
            user.subscription_status = 'free'
            db.session.commit()

    return "OK", 200

# ==============================
#      SOCKET EVENTS (UPDATED)
# ==============================

@socketio.on('join')
def on_join(data):
    room = data.get('room')
    if room:
        join_room(room)

@socketio.on('send_message')
def handle_send_message_event(data):
    content = data.get('message', '')
    receiver_id = data.get('receiver_id')
    room = data.get('room')
    client_id = data.get('client_id')  # optional from frontend

    if not current_user.is_authenticated or not room or not content.strip():
        return

    new_msg = Message(sender_id=current_user.id, receiver_id=receiver_id, content=content.strip())
    db.session.add(new_msg)
    db.session.commit()

    emit('receive_message', {
        'id': new_msg.id,
        'client_id': client_id,
        'content': new_msg.content,
        'sender_id': current_user.id,
        # ISO string so JS can show Today/Yesterday 10:30 AM
        'timestamp': new_msg.timestamp.isoformat(),
        'status': 'sent',
        'sender_name': current_user.username
    }, room=room)

@socketio.on('typing')
def handle_typing(data):
    room = data.get('room')
    if not room:
        return
    if not current_user.is_authenticated:
        return
    emit('typing', {'sender_id': current_user.id}, room=room, include_self=False)

@socketio.on('stop_typing')
def handle_stop_typing(data):
    room = data.get('room')
    if not room:
        return
    if not current_user.is_authenticated:
        return
    emit('stop_typing', {'sender_id': current_user.id}, room=room, include_self=False)
@app.route('/payment-success')
def payment_success():
    session_id = request.args.get('session_id')
    if not session_id:
        return "Invalid session"

    session_data = stripe.checkout.Session.retrieve(session_id)
    subscription_id = session_data.get('subscription')

    user = current_user
    user.subscription_status = "active"
    user.stripe_customer_id = session_data.get("customer")
    db.session.commit()

    flash("🎉 Payment Successful! Subscription Activated.")
    return redirect(url_for('dashboard'))


@app.route('/payment-cancel')
def payment_cancel():
    flash("Payment cancelled. No charges applied.")
    return redirect(url_for('show_plans'))

# --- STATIC PAGES ---
@app.route('/about')
def about():
    return render_template('pages/about.html')

@app.route('/careers')
def careers():
    return render_template('pages/careers.html')

@app.route('/success-stories')
def success_stories():
    return render_template('pages/success_stories.html')

@app.route('/pricing')
def pricing():
    return render_template('pages/pricing.html')

@app.route('/coach-guide')
def coach_guide():
    return render_template('pages/coach_guide.html')

@app.route('/academy-guide')
def academy_guide():
    return render_template('pages/academy_guide.html')

@app.route('/safety')
def safety():
    return render_template('pages/safety.html')

@app.route('/help')
def help_center():
    return render_template('pages/help.html')

# --- ERROR HANDLERS ---
@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', error_code=404), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('error.html', error_code=500), 500
# =========================================
#      STRIPE CHECKOUT SESSION ROUTE
# =========================================
@app.route('/create-checkout-session/<plan>', methods=['POST'])
@login_required
def create_checkout_session(plan):
    try:
        price_id = None

        if plan == "basic":
            price_id = app.config['STRIPE_PRICE_BASIC']
        elif plan == "pro":
            price_id = app.config['STRIPE_PRICE_PRO']
        else:
            return "Invalid plan", 400

        session_stripe = stripe.checkout.Session.create(
            payment_method_types=['card'],
            customer_email=current_user.email,
            line_items=[{
                'price': price_id,
                'quantity': 1,
            }],
            mode='subscription',
            success_url=url_for('dashboard', _external=True),
            cancel_url=url_for('show_plans', _external=True),
        )

        return redirect(session_stripe.url, code=303)

    except Exception as e:
        return str(e), 400
db.init_app(app)
if __name__ == "__main__":
    socketio.run(app, debug=True)
