from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from datetime import datetime
from flask_ckeditor import CKEditor
import os

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = r'C:\Users\Lenovo\Documents\SOFT_PROJECT\db_backend\uploads'
app.config['ALLOWED_EXTENSIONS'] = {'pdf'}
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
    status = db.Column(db.String(100), default="draft")  
    pdf_filename = db.Column(db.String(255), nullable=True)  # Optional
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

def allowed_file(filename):
    """Check if the uploaded file is a PDF."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/', methods=['GET'])
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
        # Extract form fields
        title = request.form.get('title')
        theme = request.form.get('theme')
        content = request.form.get('content')  # Content from CKEditor
        action = request.form.get('action')  # Determines whether to submit or save as draft

        # Validate mandatory fields
        if not title or not theme or not content.strip():
            flash('Title, theme, and content are required.', 'error')
            return redirect(url_for('submit_paper'))

        # Handle optional file upload
        file = request.files.get('pdf')
        if file and not allowed_file(file.filename):
            flash('Invalid file format. Please upload a PDF.', 'error')
            return redirect(url_for('submit_paper'))

        # Save the file if provided
        filename = None
        if file:
            filename = f"{title.replace(' ', '_')}.pdf"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            try:
                file.save(file_path)
            except OSError as e:
                flash(f"Error saving file: {e}", 'error')
                return redirect(url_for('submit_paper'))

        # Determine the status: "draft" or "needs reviewer"
        status = "needs reviewer" if action == "submit" else "draft"

        # Create new Paper object
        new_paper = Paper(
            title=title,
            theme=theme,
            content=content,
            author_id=current_user.id,
            status=status,
            pdf_filename=filename  # Store the filename if a PDF is uploaded
        )

        # Add to database
        try:
            db.session.add(new_paper)
            db.session.commit()
            if status == "draft":
                flash('Paper saved to drafts successfully!', 'success')
            else:
                flash('Paper submitted successfully!', 'success')
            return redirect(url_for('my_profile'))
        except Exception as e:
            db.session.rollback()
            flash(f"Error saving paper: {e}", 'error')
            return redirect(url_for('submit_paper'))

    # If GET request, render the form
    return render_template('submit_paper.html')
    
@app.route('/drafts')
def drafts():
    drafts = Paper.query.filter_by(author_id=current_user.id, status="draft").all()
    return render_template('drafts.html', drafts=drafts)

@app.route('/edit_draft/<int:paper_id>', methods=['GET', 'POST'])
def edit_draft(paper_id):
    paper = Paper.query.get_or_404(paper_id)
    if paper.author_id != current_user.id or paper.status != "draft":
        flash('Unauthorized access!', 'error')
        return redirect(url_for('drafts'))

    if request.method == 'POST':
        paper.title = request.form.get('title')
        paper.theme = request.form.get('theme')
        paper.content = request.form.get('content')
        action = request.form.get('action')

        paper.status = "needs reviewer" if action == "submit" else "draft"
        try:
            db.session.commit()
            if paper.status == "draft":
                flash('Draft updated successfully!', 'success')
            else:
                flash('Paper submitted successfully!', 'success')
            return redirect(url_for('my_profile'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred. Please try again.', 'error')

    return render_template('submit_paper.html', paper=paper)

@app.route('/delete_draft/<int:paper_id>', methods=['POST'])
def delete_draft(paper_id):
    paper = Paper.query.get_or_404(paper_id)
    if paper.author_id != current_user.id or paper.status != "draft":
        flash('Unauthorized access!', 'error')
        return redirect(url_for('drafts'))

    try:
        db.session.delete(paper)
        db.session.commit()
        flash('Draft deleted successfully!', 'success')
        return redirect(url_for('view_drafts'))
    except Exception as e:
        db.session.rollback()
        flash('An error occurred. Please try again.', 'error')


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)