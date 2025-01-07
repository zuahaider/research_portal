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
    submission_date = db.Column(db.DateTime, default=datetime.utcnow)
    publish_date = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(100), default="draft")  
    pdf_filename = db.Column(db.String(255), nullable=True)  # Optional
    reviewers = db.relationship('Review', backref='paper', lazy=True)
    old_version_id = db.Column(db.Integer, db.ForeignKey('paper.id'), nullable=True)  # Link to the old version
    description = db.Column(db.String(500), nullable=True)  # New column for short description

    # Relationship to track old version
    old_version = db.relationship('Paper', remote_side=[id], backref='resubmitted_paper')

    def __repr__(self):
        return f'<Paper {self.title}>'

# Review Model
class Review(db.Model):
    __tablename__ = 'review'
    id = db.Column(db.Integer, primary_key=True)
    review_text = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(100), default="pending")  # e.g., pending, received
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
    status = db.Column(db.String, default="not assigned") #not assigned

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

# Notification Model
class Notification(db.Model):
    __tablename__ = 'notification'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.String(500), nullable=False)
    status = db.Column(db.String(100), default="unread")  # unread or read
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref='notifications')

    def __repr__(self):
        return f'<Notification {self.id}>'

from flask import render_template, request, redirect, url_for, flash, session, jsonify
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
    article_name = request.args.get('article_name')
    sort_by_date = request.args.get('sort_by_date', 'latest')

    # Query papers based on search/filter criteria
    query = Paper.query.filter(Paper.status == 'published')  # Only show published papers

    # Apply search filters
    if article_name:
        query = query.filter(Paper.title.contains(article_name))

    if search_query:
        query = query.filter(Paper.title.contains(search_query) | Paper.content.contains(search_query))

    if author_query:
        query = query.filter(Paper.author.first_name.like(f'%{author_query}%') | Paper.author.last_name.like(f'%{author_query}%'))

    if theme_query:
        query = query.filter(Paper.theme.contains(theme_query))

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
    # Clear specific session keys or clear the entire session
    session.pop('user_id', None)
    session.pop('role', None)
    
    # Flash a logout success message
    flash('Logged out successfully!', 'success')
    
    # Redirect to the login page
    return redirect(url_for('login'))



@app.route('/my_home', methods=['GET'])
def my_home():
    search_query = request.args.get('search')
    author_query = request.args.get('author')
    theme_query = request.args.get('theme')
    sort_by_date = request.args.get('sort_by_date', 'latest')
    article_name = request.args.get('article_name')


    query = Paper.query.filter(Paper.status == 'published')  # Only show published papers
    
    if article_name:
        query = query.filter(Paper.title.contains(article_name))

    if search_query:
        query = query.filter(Paper.title.contains(search_query) | Paper.content.contains(search_query))

    if author_query:
        query = query.filter(Paper.author.first_name.like(f'%{author_query}%') | Paper.author.last_name.like(f'%{author_query}%'))

    if theme_query:
        query = query.filter(Paper.theme.contains(theme_query))

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

@app.route('/my_profile')
def my_profile():
    # Check if the user is logged in
    if 'user_id' not in session:
        flash("Please log in to access your profile.")
        return redirect(url_for('login'))

    # Fetch the user from the database
    user = User.query.get(session['user_id'])
    
    if not user:
        flash("User not found!")
        return redirect(url_for('login'))
    
    # Render the My Profile page with role-based visibility
    return render_template('my_profile.html', user=user)

@app.route('/my_dashboard')
def my_dashboard():
   return render_template('my_dashboard.html')
#user roles each one sees differently 
#upon clicking researchers board 

@app.route('/mypaper_status')
def mypaper_status():
   return render_template('mypaper_status.html')
#viewonly cant edit
#researchers only or reseracher+reviewers


@app.route('/reviews_received')
def reviews_received():
   return render_template('reviews_received.html')
#viewonly cant edit
#researchers only or reseracher+reviewers
#if old version/any paper same thing 


@app.route('/reviewers_dashboard')
def reviewers_dashboard():
   return render_template('reviewers_dashboard.html')
#reviewers only or reseracher+reviewers


@app.route('/assigned_papers')
def assigned_papers():
   return render_template('assigned_papers.html')
#reviewers only or reseracher+reviewers

@app.route('/reviewing_page')
def reviewing_page():
   return render_template('reviewing_page.html')
#reviewers only or reseracher+reviewers
#editable only as long as paper status==under review, needs revision

@app.route('/submit_paper', methods=['GET', 'POST'])
def submit_paper():
    if request.method == 'POST':
        # Extract form fields
        title = request.form.get('title')
        theme = request.form.get('theme')
        description=request.form.get('description')
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
            description=description,
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

@app.route('/resubmit_paper/<int:paper_id>', methods=['POST'])
@login_required
def resubmit_paper(paper_id):
    paper = Paper.query.get_or_404(paper_id)
    if paper.status != "needs amendments":
        flash("This paper cannot be resubmitted.", "error")
        return redirect(url_for('my_profile'))

    new_version = Paper(
        title=paper.title,
        theme=paper.theme,
        content=paper.content,
        author_id=current_user.id,
        status="needs reviewer",
        old_version_id=paper.id,
        pdf_filename=paper.pdf_filename
    )
    try:
        paper.status = "archived"  # Mark old paper as archived
        db.session.add(new_version)
        db.session.commit()
        flash("Paper resubmitted successfully!", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error resubmitting paper: {e}", "error")

    return redirect(url_for('my_profile'))

'''
# Optionally, create a notification for the author
    notification = Notification(user_id=paper.author_id, message="Your paper has been resubmitted as an old version.")
    db.session.add(notification)
    db.session.commit()

    return "Paper resubmitted successfully."


    # Create a notification for the author
    notification = Notification(user_id=paper.author_id, message="Your paper has been resubmitted and marked as an old version.")
    db.session.add(notification)
    db.session.commit()
'''

@app.route('/mypaper_status2')
def mypaper_status2():
   return render_template('mypaper_status2.html')
#researchers only or res+rev

'''
@app.route('/reviews_received')
def reviews_received():
   return render_template('reviews_received.html')
#viewonly cant edit
#researchers only 
#if old version/any paper same thing 
'''

@app.route('/assigned_papers2')
def assigned_papers2():
   return render_template('assigned_papers2.html')
#reviewers only or researcher+reviewer

@app.route('/reviewing_page2')
def reviewing_page2():
   return render_template('reviewing_page2.html')
#reviewers only or reseracher+reviewers
#undeitable version
#for all status: old version, approved, published, rejected
#excpet for: under review, needs revision

@app.route('/notifications')
def notifications():
    user = User.query.get(current_user.id)  # Assuming you're using Flask-Login for user session
    unread_notifications = Notification.query.filter_by(user_id=user.id, status="unread").all()
    
    # Optionally, mark notifications as read when viewed
    for notification in unread_notifications:
        notification.status = "read"
    db.session.commit()

    return render_template('notifications.html', notifications=unread_notifications)

@app.route('/drafts')
def drafts():
    drafts = Paper.query.filter_by(author_id=current_user.id, status="draft").all()
    return render_template('drafts.html', drafts=drafts)

@app.route('/submit-draft/<int:draft_id>', methods=['POST'])
def submit_draft(draft_id):
    draft = Draft.query.get(draft_id)
    if not draft:
        return jsonify({"error": "Draft not found."}), 404

    # Convert draft to paper
    paper = Paper(
        title=draft.title,
        content=draft.content,
        author_id=draft.author_id,
        theme=draft.theme,
        submission_date=datetime.utcnow(),
        status="draft"
    )
    db.session.add(paper)
    db.session.delete(draft)  # Remove the draft after submission
    db.session.commit()
    return jsonify({"message": "Draft submitted successfully.", "paper_id": paper.id}), 200


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

@app.route('/admins_dashboard', methods=['GET'])
def admins_dashboard():
    # Get filters from the request arguments
    author_name = request.args.get('author_name')
    article_name = request.args.get('article_name')
    theme = request.args.get('theme')
    status = request.args.get('status')
    search_query = request.args.get('search')
    sort_by_date = request.args.get('sort_by_date', 'latest')
    
    # Build the query for fetching papers based on filters
    query = Paper.query
    
    if author_name:
        query = query.filter(Paper.author.contains(author_name))
    if article_name:
        query = query.filter(Paper.title.contains(article_name))
    if search_query:
        query = query.filter(Paper.title.contains(search_query) | Paper.content.contains(search_query))
    if theme:
        query = query.filter(Paper.theme == theme)

    if sort_by_date == 'latest':
        query = query.order_by(Paper.submission_date.desc())
    elif sort_by_date == 'oldest':
        query = query.order_by(Paper.submission_date.asc())

    if status:
        query = query.filter(Paper.status == status)
    
    papers = query.all()
    
    return render_template('admins_dashboard.html', papers=papers)

@app.route('/paper_overview', methods=['GET'])
def paper_overview():
    return render_template(paper_overview.html)

@app.route('/admin_review', methods=['GET'])
def admin_review():
    return render_template(admin_review.html)

@app.route('/final_review', methods=['GET'])
def final_review():
    return render_template(final_review.html)

@app.route('/assign_reviewer', methods=['GET'])
def assign_reviewer():
    return render_template(assign_reviewer.html)

@app.route('/view_userdetails', methods=['GET'])
def view_userdetails():
    return render_template(view_userdetails.html)

@app.route('/paper/<int:paper_id>', methods=['GET', 'POST'])
def paper_detail(paper_id):
    paper = Paper.query.get_or_404(paper_id)
    
    if request.method == 'POST':
        status = request.form['status']
        paper.status = status
        db.session.commit()
        flash('Status updated successfully!', 'success')
    
    return render_template('paper_detail.html', paper=paper)

@app.route('/paper/<int:paper_id>/add_review', methods=['POST'])
def add_review(paper_id):
    paper = Paper.query.get_or_404(paper_id)
    
    if request.method == 'POST':
        review_content = request.form['review']
        new_review = Review(content=review_content, paper_id=paper.id, reviewer_id=current_user.id)
        db.session.add(new_review)
        db.session.commit()
        flash('Review added successfully!', 'success')
    
    return redirect(url_for('paper_detail', paper_id=paper.id))

def assign_reviewer(paper_id, reviewer_id):
    # Create a notification for the reviewer
    notification = Notification(user_id=reviewer_id, message=f"You have been assigned to review the paper {paper_id}.")
    db.session.add(notification)
    db.session.commit()

def update_paper_status(paper_id, new_status):
    paper = Paper.query.get(paper_id)
    paper.status = new_status
    db.session.commit()

    # Create a notification for the author
    notification = Notification(user_id=paper.author_id, message=f"Your paper status has been updated to {new_status}.")
    db.session.add(notification)
    db.session.commit()

@app.route('/notifications/<int:user_id>', methods=['GET'])
def get_notifications(user_id):
    notifications = Notification.query.filter_by(user_id=user_id, status="unread").all()
    return jsonify([{
        "id": n.id,
        "message": n.message,
        "timestamp": n.timestamp
    } for n in notifications])

@app.route('/notifications/mark-as-read/<int:notification_id>', methods=['POST'])
def mark_notification_as_read(notification_id):
    notification = Notification.query.get(notification_id)
    if notification:
        notification.status = "read"
        db.session.commit()
        return jsonify({"message": "Notification marked as read."}), 200
    return jsonify({"error": "Notification not found."}), 404


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)