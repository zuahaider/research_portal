from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from datetime import datetime
from flask_ckeditor import CKEditor

app = Flask(__name__)
app.config['SECRET_KEY'] = 'my_secret_key'  
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///research_portal.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['CKEDITOR_PKG_TYPE'] = 'full'  # Includes all toolbar options
ckeditor = CKEditor(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# User Model
class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    preferences = db.Column(db.String(100), nullable=False)  # e.g., Natural, Social, Formal
    role = db.Column(db.String(50), nullable=False, default='researcher')  # admin, researcher, reviewer
    papers = db.relationship('Paper', backref='author', lazy=True)
    reviews = db.relationship('Review', backref='reviewer', lazy=True)
    approved_papers = db.Column(db.Integer, default=0)
    assigned_papers = db.Column(db.Integer, default=0)

    def __repr__(self):
        return f'<User {self.email}>'

# Paper Model
class Paper(db.Model):
    __tablename__ = 'paper'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    theme = db.Column(db.String(100), nullable=False)
    publish_date = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(100), default="needs reviewer")  # e.g., needs reviewer, approved, etc.
    reviewers = db.relationship('Review', backref='paper', lazy=True)

    def __repr__(self):
        return f'<Paper {self.title}>'

# Review Model
class Review(db.Model):
    __tablename__ = 'review'
    id = db.Column(db.Integer, primary_key=True)
    review_text = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(100), default="pending")  # e.g., pending, completed
    reviewer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    paper_id = db.Column(db.Integer, db.ForeignKey('paper.id'), nullable=False)
    review_date = db.Column(db.Date, default=datetime.utcnow)

    def __repr__(self):
        return f'<Review {self.id}>'

# ReviewerAssignment Model
class ReviewerAssignment(db.Model):
    __tablename__ = 'reviewer_assignments'
    assignment_id = db.Column(db.Integer, primary_key=True)
    paper_id = db.Column(db.Integer, db.ForeignKey('paper.id'), nullable=False)
    reviewer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String, default="assigned")

    def __repr__(self):
        return f'<ReviewerAssignment {self.assignment_id}>'
    
# StatusHistory Model
class StatusHistory(db.Model):
    __tablename__ = 'status_history'
    history_id = db.Column(db.Integer, primary_key=True)
    paper_id = db.Column(db.Integer, db.ForeignKey('paper.id'), nullable=False)
    status = db.Column(db.String, nullable=False)
    changed_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    change_date = db.Column(db.Date, default=datetime.utcnow)

    def __repr__(self):
        return f'<StatusHistory {self.history_id}>'

# Draft Model
class Draft(db.Model):
    __tablename__ = 'draft'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    theme = db.Column(db.String(100), nullable=False)
    draft_date = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Draft {self.title}>'

from flask import render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user

login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/research_page', methods=['GET'])
def research_page():
    search_query = request.args.get('search')
    author_query = request.args.get('author')
    theme_query = request.args.get('theme')
    sort_by_date = request.args.get('sort_by_date', 'latest')

    # Query papers based on search/filter criteria
    query = Paper.query

    # Search by title/content
    if search_query:
        query = query.filter(Paper.title.contains(search_query) | Paper.content.contains(search_query))

    # Filter by author (first_name + last_name)
    if author_query:
        first_name, last_name = author_query.split(" ", 1)
        query = query.filter(Paper.author.first_name.like(f'%{first_name}%'),
                             Paper.author.last_name.like(f'%{last_name}%'))

    # Filter by theme
    if theme_query:
        query = query.filter(Paper.theme.contains(theme_query))

    # Sorting by date
    if sort_by_date == 'latest':
        query = query.order_by(Paper.publish_date.desc())
    elif sort_by_date == 'oldest':
        query = query.order_by(Paper.publish_date.asc())

    papers = query.all()

    return render_template('research_page.html', papers=papers)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        preferences = request.form.getlist('preferences')  # Get selected preferences as a list
        
        # Check preferences length, must be at least one
        if len(preferences) < 1:
            flash('Please select at least one preference.', 'danger')
            return render_template('register.html')
        
        # Validate password length
        if len(password) < 4 or len(password) > 10:
            flash('Password must be between 4 and 10 characters.', 'danger')
            return render_template('register.html')

        # Check if the email already exists in the database
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('This email is already registered. Please login or use a different email.', 'danger')
            return render_template('register.html')

        # Hash password
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        # If email is admin, set as admin user
        if email == 'admin@gmail.com':
            role = 'admin'
            new_user = User(
                email=email, 
                password=hashed_password, 
                first_name='admin', 
                last_name='editor', 
                preferences=', '.join(preferences),  # Convert list to comma-separated string
                role=role
            )
        else:
            role = 'researcher'  # Default role for others
            new_user = User(
                email=email, 
                password=hashed_password, 
                first_name=first_name, 
                last_name=last_name, 
                preferences=', '.join(preferences),  # Convert list to comma-separated string
                role=role
            )

        # Add user to the database
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('User registered successfully!', 'success')
            return redirect(url_for('login'))  # Redirect to login page after successful registration
        except Exception as e:
            db.session.rollback()  # Rollback in case of any error
            flash(f'Error: {str(e)}', 'danger')

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['role'] = user.role
            return redirect(url_for('my_home'))
        else:
            flash("Invalid email or password.", "error")
            return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('role', None)
    flash("Logged out successfully.", "success")
    return redirect(url_for('logout'))

@app.route('/my_home', methods=['GET'])
def my_home():
    search_query = request.args.get('search')
    author_query = request.args.get('author')
    theme_query = request.args.get('theme')
    sort_by_date = request.args.get('sort_by_date', 'latest')

    # Query papers based on search/filter criteria
    query = Paper.query

    # Search by title/content
    if search_query:
        query = query.filter(Paper.title.contains(search_query) | Paper.content.contains(search_query))

    # Filter by author (first_name + last_name)
    if author_query:
        first_name, last_name = author_query.split(" ", 1)
        query = query.filter(Paper.author.first_name.like(f'%{first_name}%'),
                             Paper.author.last_name.like(f'%{last_name}%'))

    # Filter by theme
    if theme_query:
        query = query.filter(Paper.theme.contains(theme_query))

    # Sorting by date
    if sort_by_date == 'latest':
        query = query.order_by(Paper.publish_date.desc())
    elif sort_by_date == 'oldest':
        query = query.order_by(Paper.publish_date.asc())

    papers = query.all()

    return render_template('my_home.html', papers=papers)

@app.route('/view_paper/<int:paper_id>', methods=['GET'])
def view_paper(paper_id):
    paper = Paper.query.get_or_404(paper_id)
    return render_template('view_paper.html', paper=paper)

@app.route('/my_profile', methods=['GET', 'POST'])
def my_profile():
    return render_template('my_profile.html')

@app.route('/my_progress')
def my_progress():
    if current_user.role == 'admin':
        # Admin view: see all papers and manage reviewers and publishing
        papers = Paper.query.filter(Paper.status.in_(['needs_reviewer', 'under_review', 'needs_revision', 'approved'])).all()
        all_users = User.query.filter(User.role != 'admin').all()  # To select reviewers

    elif current_user.role == 'researcher' or current_user.role == 'reviewer':
        # Researcher view: see their own papers
        papers = Paper.query.filter_by(author_id=current_user.id).all()
        # If the user is also a reviewer, fetch assigned papers
        assigned_papers = None
        if current_user.role == 'reviewer':
            assigned_papers = ReviewerAssignment.query.filter_by(reviewer_id=current_user.id).all()

    return render_template(
        'my_progress.html',
        papers=papers,
        assigned_papers=assigned_papers if current_user.role == 'reviewer' else None,
        all_users=all_users if current_user.role == 'admin' else None
    )

@app.route('/submit_paper', methods=['GET', 'POST'])
def submit_paper():
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')  # Content from CKEditor
        # Save the title and content to the database (not shown here)

        flash('Paper submitted successfully!')
        return redirect(url_for('my_profile'))
    return render_template('submit_paper.html')

@app.route('/drafts')
def drafts():
    # Placeholder for drafts functionality
    return "Drafts Page (Coming Soon)"

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)