from os import abort
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import collections
import json
import sqlite3
import hashlib
import re
from datetime import datetime
from email_validator import validate_email, EmailNotValidError
import phonenumbers
from datetime import datetime, timezone

app = Flask(__name__)
app.secret_key = '123456789' 
DATABASE = 'database.sqlite'

# Load censorship data
# WARNING! The censorship.dat file contains disturbing language when decrypted. 
# If you want to test whether moderation works, 
# you can trigger censorship using these words: 
# tier1badword, tier2badword, tier3badword
ENCRYPTED_FILE_PATH = 'censorship.dat'
fernet = Fernet('xpplx11wZUibz0E8tV8Z9mf-wwggzSrc21uQ17Qq2gg=')
with open(ENCRYPTED_FILE_PATH, 'rb') as encrypted_file:
    encrypted_data = encrypted_file.read()
decrypted_data = fernet.decrypt(encrypted_data)
MODERATION_CONFIG = json.loads(decrypted_data)
TIER1_WORDS = MODERATION_CONFIG['categories']['tier1_severe_violations']['words']
TIER2_PHRASES = MODERATION_CONFIG['categories']['tier2_spam_scams']['phrases']
TIER3_WORDS = MODERATION_CONFIG['categories']['tier3_mild_profanity']['words']

def get_db():
    """
    Connect to the application's configured database. The connection
    is unique for each request and will be reused if this is called
    again.
    """
    if 'db' not in g:
        g.db = sqlite3.connect(
            DATABASE,
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        g.db.row_factory = sqlite3.Row

    return g.db


@app.teardown_appcontext
def close_connection(exception):
    """Closes the database again at the end of the request."""
    db = g.pop('db', None)

    if db is not None:
        db.close()


def query_db(query, args=(), one=False, commit=False):
    """
    Queries the database and returns a list of dictionaries, a single
    dictionary, or None. Also handles write operations.
    """
    db = get_db()
    
    # Using 'with' on a connection object implicitly handles transactions.
    # The 'with' statement will automatically commit if successful, 
    # or rollback if an exception occurs. This is safer.
    try:
        with db:
            cur = db.execute(query, args)
        
        # For SELECT statements, fetch the results after the transaction block
        if not commit:
            rv = cur.fetchall()
            return (rv[0] if rv else None) if one else rv
        
        # For write operations, we might want the cursor to get info like lastrowid
        return cur

    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return None

@app.template_filter('datetimeformat')
def datetimeformat(value):
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, str):
        dt = datetime.strptime(value, '%Y-%m-%d %H:%M:%S')
    else:
        return "N/A"
    return dt.strftime('%b %d, %Y %H:%M')

REACTION_EMOJIS = {
    'like': '❤️', 'love': '😍', 'laugh': '😂',
    'wow': '😮', 'sad': '😢', 'angry': '😠',
}
REACTION_TYPES = list(REACTION_EMOJIS.keys())


@app.route('/')
def feed():
    #  1. Get Pagination and Filter Parameters 
    try:
        page = int(request.args.get('page', 1))
    except ValueError:
        page = 1
    sort = request.args.get('sort', 'new').lower()
    show = request.args.get('show', 'all').lower()
    
    # Define how many posts to show per page
    POSTS_PER_PAGE = 10
    offset = (page - 1) * POSTS_PER_PAGE

    current_user_id = session.get('user_id')
    params = []

    #  2. Build the Query 
    where_clause = ""
    if show == 'following' and current_user_id:
        where_clause = "WHERE p.user_id IN (SELECT followed_id FROM follows WHERE follower_id = ?)"
        params.append(current_user_id)

    # Add the pagination parameters to the query arguments
    pagination_params = (POSTS_PER_PAGE, offset)

    # Handle recommended posts differently
    if sort == 'recommended':
        # Get recommended posts (already processed by recommend function)
        recommended_posts = recommend(current_user_id, show == 'following' and current_user_id)
        
        posts_data = []
        for rec_post in recommended_posts:
            # Get additional data for each recommended post
            post_id = rec_post['id']
            
            # Determine if the current user follows the poster
            followed_poster = False
            if current_user_id and rec_post['user_id'] != current_user_id:
                follow_check = query_db(
                    'SELECT 1 FROM follows WHERE follower_id = ? AND followed_id = ?',
                    (current_user_id, rec_post['user_id']),
                    one=True
                )
                if follow_check:
                    followed_poster = True

            # Determine if the current user reacted to this post
            user_reaction = None
            if current_user_id:
                reaction_check = query_db(
                    'SELECT reaction_type FROM reactions WHERE user_id = ? AND post_id = ?',
                    (current_user_id, post_id),
                    one=True
                )
                if reaction_check:
                    user_reaction = reaction_check['reaction_type']

            # Get reactions and comments
            reactions = query_db('SELECT reaction_type, COUNT(*) as count FROM reactions WHERE post_id = ? GROUP BY reaction_type', (post_id,))
            comments_raw = query_db('SELECT c.id, c.content, c.created_at, u.username, u.id as user_id FROM comments c JOIN users u ON c.user_id = u.id WHERE c.post_id = ? ORDER BY c.created_at ASC', (post_id,))
            
            comments_moderated = []
            for comment in comments_raw:
                comment_dict = dict(comment)
                comment_dict['content'], _ = moderate_content(comment_dict['content'])
                comments_moderated.append(comment_dict)
            
            posts_data.append({
                'post': rec_post,  # Already has content moderated
                'reactions': reactions,
                'user_reaction': user_reaction,
                'followed_poster': followed_poster,
                'comments': comments_moderated
            })
        
        return render_template('feed.html.j2', 
                               posts=posts_data, 
                               current_sort=sort,
                               current_show=show,
                               page=page,
                               per_page=POSTS_PER_PAGE,
                               reaction_emojis=REACTION_EMOJIS,
                               reaction_types=REACTION_TYPES)
    
    # Handle popular and new posts (original logic)
    if sort == 'popular':
        query = f"""
            SELECT p.id, p.content, p.created_at, u.username, u.id as user_id,
                   IFNULL(r.total_reactions, 0) as total_reactions
            FROM posts p
            JOIN users u ON p.user_id = u.id
            LEFT JOIN (
                SELECT post_id, COUNT(*) as total_reactions FROM reactions GROUP BY post_id
            ) r ON p.id = r.post_id
            {where_clause}
            ORDER BY total_reactions DESC, p.created_at DESC
            LIMIT ? OFFSET ?
        """
        final_params = params + list(pagination_params)
        posts = query_db(query, final_params)
    else:  # Default sort is 'new'
        query = f"""
            SELECT p.id, p.content, p.created_at, u.username, u.id as user_id
            FROM posts p
            JOIN users u ON p.user_id = u.id
            {where_clause}
            ORDER BY p.created_at DESC
            LIMIT ? OFFSET ?
        """
        final_params = params + list(pagination_params)
        posts = query_db(query, final_params)

    posts_data = []
    for post in posts:
        # Determine if the current user follows the poster
        followed_poster = False
        if current_user_id and post['user_id'] != current_user_id:
            follow_check = query_db(
                'SELECT 1 FROM follows WHERE follower_id = ? AND followed_id = ?',
                (current_user_id, post['user_id']),
                one=True
            )
            if follow_check:
                followed_poster = True

        # Determine if the current user reacted to this post and with what reaction
        user_reaction = None
        if current_user_id:
            reaction_check = query_db(
                'SELECT reaction_type FROM reactions WHERE user_id = ? AND post_id = ?',
                (current_user_id, post['id']),
                one=True
            )
            if reaction_check:
                user_reaction = reaction_check['reaction_type']

        reactions = query_db('SELECT reaction_type, COUNT(*) as count FROM reactions WHERE post_id = ? GROUP BY reaction_type', (post['id'],))
        comments_raw = query_db('SELECT c.id, c.content, c.created_at, u.username, u.id as user_id FROM comments c JOIN users u ON c.user_id = u.id WHERE c.post_id = ? ORDER BY c.created_at ASC', (post['id'],))
        post_dict = dict(post)
        post_dict['content'], _ = moderate_content(post_dict['content'])
        comments_moderated = []
        for comment in comments_raw:
            comment_dict = dict(comment)
            comment_dict['content'], _ = moderate_content(comment_dict['content'])
            comments_moderated.append(comment_dict)
        posts_data.append({
            'post': post_dict,
            'reactions': reactions,
            'user_reaction': user_reaction,
            'followed_poster': followed_poster,
            'comments': comments_moderated
        })

    #  4. Render Template with Pagination Info 
    return render_template('feed.html.j2', 
                           posts=posts_data, 
                           current_sort=sort,
                           current_show=show,
                           page=page,
                           per_page=POSTS_PER_PAGE,
                           reaction_emojis=REACTION_EMOJIS,
                           reaction_types=REACTION_TYPES)

@app.route('/posts/new', methods=['POST'])
def add_post():
    """Handles creating a new post from the feed."""
    user_id = session.get('user_id')

    # Block access if user is not logged in
    if not user_id:
        flash('You must be logged in to create a post.', 'danger')
        return redirect(url_for('login'))

    # Get content from the submitted form
    content = request.form.get('content')

    # Pass the user's content through the moderation function
    moderated_content = content

    # Basic validation to ensure post is not empty
    if moderated_content and moderated_content.strip():
        db = get_db()
        db.execute('INSERT INTO posts (user_id, content) VALUES (?, ?)',
                   (user_id, moderated_content))
        db.commit()
        flash('Your post was successfully created!', 'success')
    else:
        # This will catch empty posts or posts that were fully censored
        flash('Post cannot be empty or was fully censored.', 'warning')

    # Redirect back to the main feed to see the new post
    return redirect(url_for('feed'))
    
    
@app.route('/posts/<int:post_id>/delete', methods=['POST'])
def delete_post(post_id):
    """Handles deleting a post."""
    user_id = session.get('user_id')

    # Block access if user is not logged in
    if not user_id:
        flash('You must be logged in to delete a post.', 'danger')
        return redirect(url_for('login'))

    # Find the post in the database
    post = query_db('SELECT id, user_id FROM posts WHERE id = ?', (post_id,), one=True)

    # Check if the post exists and if the current user is the owner
    if not post:
        flash('Post not found.', 'danger')
        return redirect(url_for('feed'))

    if post['user_id'] != user_id:
        # Security check: prevent users from deleting others' posts
        flash('You do not have permission to delete this post.', 'danger')
        return redirect(url_for('feed'))

    # If all checks pass, proceed with deletion
    db = get_db()
    # To maintain database integrity, delete associated records first
    db.execute('DELETE FROM comments WHERE post_id = ?', (post_id,))
    db.execute('DELETE FROM reactions WHERE post_id = ?', (post_id,))
    # Finally, delete the post itself
    db.execute('DELETE FROM posts WHERE id = ?', (post_id,))
    db.commit()

    flash('Your post was successfully deleted.', 'success')
    # Redirect back to the page the user came from, or the feed as a fallback
    return redirect(request.referrer or url_for('feed'))

@app.route('/u/<username>')
def user_profile(username):
    """Displays a user's profile page with moderated bio, posts, and latest comments."""
    
    user_raw = query_db('SELECT * FROM users WHERE username = ?', (username,), one=True)
    if not user_raw:
        abort(404)

    user = dict(user_raw)
    moderated_bio, _ = moderate_content(user.get('profile', ''))
    user['profile'] = moderated_bio

    posts_raw = query_db('SELECT id, content, user_id, created_at FROM posts WHERE user_id = ? ORDER BY created_at DESC', (user['id'],))
    posts = []
    for post_raw in posts_raw:
        post = dict(post_raw)
        moderated_post_content, _ = moderate_content(post['content'])
        post['content'] = moderated_post_content
        posts.append(post)

    comments_raw = query_db('SELECT id, content, user_id, post_id, created_at FROM comments WHERE user_id = ? ORDER BY created_at DESC LIMIT 100', (user['id'],))
    comments = []
    for comment_raw in comments_raw:
        comment = dict(comment_raw)
        moderated_comment_content, _ = moderate_content(comment['content'])
        comment['content'] = moderated_comment_content
        comments.append(comment)

    followers_count = query_db('SELECT COUNT(*) as cnt FROM follows WHERE followed_id = ?', (user['id'],), one=True)['cnt']
    following_count = query_db('SELECT COUNT(*) as cnt FROM follows WHERE follower_id = ?', (user['id'],), one=True)['cnt']

    #  NEW: CHECK FOLLOW STATUS 
    is_currently_following = False # Default to False
    current_user_id = session.get('user_id')
    
    # We only need to check if a user is logged in
    if current_user_id:
        follow_relation = query_db(
            'SELECT 1 FROM follows WHERE follower_id = ? AND followed_id = ?',
            (current_user_id, user['id']),
            one=True
        )
        if follow_relation:
            is_currently_following = True
    # --

    return render_template('user_profile.html.j2', 
                           user=user, 
                           posts=posts, 
                           comments=comments,
                           followers_count=followers_count, 
                           following_count=following_count,
                           is_following=is_currently_following)
    

@app.route('/u/<username>/followers')
def user_followers(username):
    user = query_db('SELECT * FROM users WHERE username = ?', (username,), one=True)
    if not user:
        abort(404)
    followers = query_db('''
        SELECT u.username
        FROM follows f
        JOIN users u ON f.follower_id = u.id
        WHERE f.followed_id = ?
    ''', (user['id'],))
    return render_template('user_list.html.j2', user=user, users=followers, title="Followers of")

@app.route('/u/<username>/following')
def user_following(username):
    user = query_db('SELECT * FROM users WHERE username = ?', (username,), one=True)
    if not user:
        abort(404)
    following = query_db('''
        SELECT u.username
        FROM follows f
        JOIN users u ON f.followed_id = u.id
        WHERE f.follower_id = ?
    ''', (user['id'],))
    return render_template('user_list.html.j2', user=user, users=following, title="Users followed by")

@app.route('/posts/<int:post_id>')
def post_detail(post_id):
    """Displays a single post and its comments, with content moderation applied."""
    
    post_raw = query_db('''
        SELECT p.id, p.content, p.created_at, u.username, u.id as user_id
        FROM posts p
        JOIN users u ON p.user_id = u.id
        WHERE p.id = ?
    ''', (post_id,), one=True)

    if not post_raw:
        # The abort function will stop the request and show a 404 Not Found page.
        abort(404)

    #  Moderation for the Main Post 
    # Convert the raw database row to a mutable dictionary
    post = dict(post_raw)
    # Unpack the tuple from moderate_content, we only need the moderated content string here
    moderated_post_content, _ = moderate_content(post['content'])
    post['content'] = moderated_post_content

    #  Fetch Reactions (No moderation needed) 
    reactions = query_db('''
        SELECT reaction_type, COUNT(*) as count
        FROM reactions
        WHERE post_id = ?
        GROUP BY reaction_type
    ''', (post_id,))

    #  Fetch and Moderate Comments 
    comments_raw = query_db('SELECT c.id, c.content, c.created_at, u.username, u.id as user_id FROM comments c JOIN users u ON c.user_id = u.id WHERE c.post_id = ? ORDER BY c.created_at ASC', (post_id,))
    
    comments = [] # Create a new list for the moderated comments
    for comment_raw in comments_raw:
        comment = dict(comment_raw) # Convert to a dictionary
        # Moderate the content of each comment
        print(comment['content'])
        moderated_comment_content, _ = moderate_content(comment['content'])
        comment['content'] = moderated_comment_content
        comments.append(comment)

    # Pass the moderated data to the template
    return render_template('post_detail.html.j2',
                           post=post,
                           reactions=reactions,
                           comments=comments,
                           reaction_emojis=REACTION_EMOJIS,
                           reaction_types=REACTION_TYPES)

@app.route('/about')
def about():
    return render_template('about.html.j2')

@app.route('/privacy')
def privacy():
    return render_template('privacy.html.j2')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        location = request.form.get('location', '')
        birthdate = request.form.get('birthdate', '')
        profile = request.form.get('profile', '')

        hashed_password = generate_password_hash(password)

        db = get_db()
        cur = db.cursor()
        try:
            cur.execute(
                'INSERT INTO users (username, password, location, birthdate, profile) VALUES (?, ?, ?, ?, ?)',
                (username, hashed_password, location, birthdate, profile)
            )
            db.commit()

            # 1. Get the ID of the user we just created.
            new_user_id = cur.lastrowid

            # 2. Add user info to the session cookie.
            session.clear() # Clear any old session data
            session['user_id'] = new_user_id
            session['username'] = username

            # 3. Flash a welcome message and redirect to the feed.
            flash(f'Welcome, {username}! Your account has been created.', 'success')
            return redirect(url_for('feed')) # Redirect to the main feed/dashboard

        except sqlite3.IntegrityError:
            flash('Username already taken. Please choose another one.', 'danger')
        finally:
            cur.close()
            db.close()
            
    return render_template('signup.html.j2')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        db.close()

        # 1. Check if the user exists.
        # 2. If user exists, use check_password_hash to securely compare the password.
        #    This function handles the salt and prevents timing attacks.
        if user and check_password_hash(user['password'], password):
            # Password is correct!
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash('Logged in successfully.', 'success')
            return redirect(url_for('feed'))
        else:
            # User does not exist or password was incorrect.
            flash('Invalid username or password.', 'danger')
            
    return render_template('login.html.j2')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/posts/<int:post_id>/comment', methods=['POST'])
def add_comment(post_id):
    """Handles adding a new comment to a specific post."""
    user_id = session.get('user_id')

    # Block access if user is not logged in
    if not user_id:
        flash('You must be logged in to comment.', 'danger')
        return redirect(url_for('login'))

    # Get content from the submitted form
    content = request.form.get('content')

    # Basic validation to ensure comment is not empty
    if content and content.strip():
        db = get_db()
        db.execute('INSERT INTO comments (post_id, user_id, content) VALUES (?, ?, ?)',
                   (post_id, user_id, content))
        db.commit()
        flash('Your comment was added.', 'success')
    else:
        flash('Comment cannot be empty.', 'warning')

    # Redirect back to the page the user came from (likely the post detail page)
    return redirect(request.referrer or url_for('post_detail', post_id=post_id))

@app.route('/comments/<int:comment_id>/delete', methods=['POST'])
def delete_comment(comment_id):
    """Handles deleting a comment."""
    user_id = session.get('user_id')

    # Block access if user is not logged in
    if not user_id:
        flash('You must be logged in to delete a comment.', 'danger')
        return redirect(url_for('login'))

    # Find the comment and the original post's author ID
    comment = query_db('''
        SELECT c.id, c.user_id, p.user_id as post_author_id
        FROM comments c
        JOIN posts p ON c.post_id = p.id
        WHERE c.id = ?
    ''', (comment_id,), one=True)

    # Check if the comment exists
    if not comment:
        flash('Comment not found.', 'danger')
        return redirect(request.referrer or url_for('feed'))

    # Security Check: Allow deletion if the user is the comment's author OR the post's author
    if user_id != comment['user_id'] and user_id != comment['post_author_id']:
        flash('You do not have permission to delete this comment.', 'danger')
        return redirect(request.referrer or url_for('feed'))

    # If all checks pass, proceed with deletion
    db = get_db()
    db.execute('DELETE FROM comments WHERE id = ?', (comment_id,))
    db.commit()

    flash('Comment successfully deleted.', 'success')
    # Redirect back to the page the user came from
    return redirect(request.referrer or url_for('feed'))

@app.route('/react', methods=['POST'])
def add_reaction():
    """Handles adding a new reaction or updating an existing one."""
    user_id = session.get('user_id')

    if not user_id:
        flash("You must be logged in to react.", "danger")
        return redirect(url_for('login'))

    post_id = request.form.get('post_id')
    new_reaction_type = request.form.get('reaction')

    if not post_id or not new_reaction_type:
        flash("Invalid reaction request.", "warning")
        return redirect(request.referrer or url_for('feed'))

    db = get_db()

    # Step 1: Check if a reaction from this user already exists on this post.
    existing_reaction = query_db('SELECT id FROM reactions WHERE post_id = ? AND user_id = ?',
                                 (post_id, user_id), one=True)

    if existing_reaction:
        # Step 2: If it exists, UPDATE the reaction_type.
        db.execute('UPDATE reactions SET reaction_type = ? WHERE id = ?',
                   (new_reaction_type, existing_reaction['id']))
    else:
        # Step 3: If it does not exist, INSERT a new reaction.
        db.execute('INSERT INTO reactions (post_id, user_id, reaction_type) VALUES (?, ?, ?)',
                   (post_id, user_id, new_reaction_type))

    db.commit()

    return redirect(request.referrer or url_for('feed'))

@app.route('/unreact', methods=['POST'])
def unreact():
    """Handles removing a user's reaction from a post."""
    user_id = session.get('user_id')

    if not user_id:
        flash("You must be logged in to unreact.", "danger")
        return redirect(url_for('login'))

    post_id = request.form.get('post_id')

    if not post_id:
        flash("Invalid unreact request.", "warning")
        return redirect(request.referrer or url_for('feed'))

    db = get_db()

    # Remove the reaction if it exists
    existing_reaction = query_db(
        'SELECT id FROM reactions WHERE post_id = ? AND user_id = ?',
        (post_id, user_id),
        one=True
    )

    if existing_reaction:
        db.execute('DELETE FROM reactions WHERE id = ?', (existing_reaction['id'],))
        db.commit()
        flash("Reaction removed.", "success")
    else:
        flash("No reaction to remove.", "info")

    return redirect(request.referrer or url_for('feed'))


@app.route('/u/<int:user_id>/follow', methods=['POST'])
def follow_user(user_id):
    """Handles the logic for the current user to follow another user."""
    follower_id = session.get('user_id')

    # Security: Ensure user is logged in
    if not follower_id:
        flash("You must be logged in to follow users.", "danger")
        return redirect(url_for('login'))

    # Security: Prevent users from following themselves
    if follower_id == user_id:
        flash("You cannot follow yourself.", "warning")
        return redirect(request.referrer or url_for('feed'))

    # Check if the user to be followed actually exists
    user_to_follow = query_db('SELECT id FROM users WHERE id = ?', (user_id,), one=True)
    if not user_to_follow:
        flash("The user you are trying to follow does not exist.", "danger")
        return redirect(request.referrer or url_for('feed'))
        
    db = get_db()
    try:
        # Insert the follow relationship. The PRIMARY KEY constraint will prevent duplicates if you've set one.
        db.execute('INSERT INTO follows (follower_id, followed_id) VALUES (?, ?)',
                   (follower_id, user_id))
        db.commit()
        username_to_follow = query_db('SELECT username FROM users WHERE id = ?', (user_id,), one=True)['username']
        flash(f"You are now following {username_to_follow}.", "success")
    except sqlite3.IntegrityError:
        flash("You are already following this user.", "info")

    return redirect(request.referrer or url_for('feed'))


@app.route('/u/<int:user_id>/unfollow', methods=['POST'])
def unfollow_user(user_id):
    """Handles the logic for the current user to unfollow another user."""
    follower_id = session.get('user_id')

    # Security: Ensure user is logged in
    if not follower_id:
        flash("You must be logged in to unfollow users.", "danger")
        return redirect(url_for('login'))

    db = get_db()
    cur = db.execute('DELETE FROM follows WHERE follower_id = ? AND followed_id = ?',
               (follower_id, user_id))
    db.commit()

    if cur.rowcount > 0:
        # cur.rowcount tells us if a row was actually deleted
        username_unfollowed = query_db('SELECT username FROM users WHERE id = ?', (user_id,), one=True)['username']
        flash(f"You have unfollowed {username_unfollowed}.", "success")
    else:
        # This case handles if someone tries to unfollow a user they weren't following
        flash("You were not following this user.", "info")

    # Redirect back to the page the user came from
    return redirect(request.referrer or url_for('feed'))

@app.route('/admin')
def admin_dashboard():
    """Displays the admin dashboard with users, posts, and comments, sorted by risk."""

    if session.get('username') != 'admin':
        flash("You do not have permission to access this page.", "danger")
        return redirect(url_for('feed'))

    RISK_LEVELS = { "HIGH": 5, "MEDIUM": 3, "LOW": 1 }
    PAGE_SIZE = 50

    def get_risk_profile(score):
        if score >= RISK_LEVELS["HIGH"]:
            return "HIGH", 3
        elif score >= RISK_LEVELS["MEDIUM"]:
            return "MEDIUM", 2
        elif score >= RISK_LEVELS["LOW"]:
            return "LOW", 1
        return "NONE", 0

    # Get pagination and current tab parameters
    try:
        users_page = int(request.args.get('users_page', 1))
        posts_page = int(request.args.get('posts_page', 1))
        comments_page = int(request.args.get('comments_page', 1))
    except ValueError:
        users_page = 1
        posts_page = 1
        comments_page = 1
    
    current_tab = request.args.get('tab', 'users') # Default to 'users' tab

    users_offset = (users_page - 1) * PAGE_SIZE
    
    # First, get all users to calculate risk, then apply pagination in Python
    # It's more complex to do this efficiently in SQL if risk calc is Python-side
    all_users_raw = query_db('SELECT id, username, profile, created_at FROM users')
    all_users = []
    for user in all_users_raw:
        user_dict = dict(user)
        user_risk_score = user_risk_analysis(user_dict['id'])
        risk_label, risk_sort_key = get_risk_profile(user_risk_score)
        user_dict['risk_label'] = risk_label
        user_dict['risk_sort_key'] = risk_sort_key
        user_dict['risk_score'] = min(5.0, round(user_risk_score, 2))
        all_users.append(user_dict)

    all_users.sort(key=lambda x: x['risk_score'], reverse=True)
    total_users = len(all_users)
    users = all_users[users_offset : users_offset + PAGE_SIZE]
    total_users_pages = (total_users + PAGE_SIZE - 1) // PAGE_SIZE

    # --- Posts Tab Data ---
    posts_offset = (posts_page - 1) * PAGE_SIZE
    total_posts_count = query_db('SELECT COUNT(*) as count FROM posts', one=True)['count']
    total_posts_pages = (total_posts_count + PAGE_SIZE - 1) // PAGE_SIZE

    posts_raw = query_db(f'''
        SELECT p.id, p.content, p.created_at, u.username, u.created_at as user_created_at
        FROM posts p JOIN users u ON p.user_id = u.id
        ORDER BY p.id DESC -- Order by ID for consistent pagination before risk sort
        LIMIT ? OFFSET ?
    ''', (PAGE_SIZE, posts_offset))
    posts = []
    for post in posts_raw:
        post_dict = dict(post)
        _, base_score = moderate_content(post_dict['content'])
        final_score = base_score 
        author_created_dt = post_dict['user_created_at']
        author_age_days = (datetime.utcnow() - author_created_dt).days
        if author_age_days < 7:
            final_score *= 1.5
        risk_label, risk_sort_key = get_risk_profile(final_score)
        post_dict['risk_label'] = risk_label
        post_dict['risk_sort_key'] = risk_sort_key
        post_dict['risk_score'] = round(final_score, 2)
        posts.append(post_dict)

    posts.sort(key=lambda x: x['risk_score'], reverse=True) # Sort after fetching and scoring

    # --- Comments Tab Data ---
    comments_offset = (comments_page - 1) * PAGE_SIZE
    total_comments_count = query_db('SELECT COUNT(*) as count FROM comments', one=True)['count']
    total_comments_pages = (total_comments_count + PAGE_SIZE - 1) // PAGE_SIZE

    comments_raw = query_db(f'''
        SELECT c.id, c.content, c.created_at, u.username, u.created_at as user_created_at
        FROM comments c JOIN users u ON c.user_id = u.id
        ORDER BY c.id DESC -- Order by ID for consistent pagination before risk sort
        LIMIT ? OFFSET ?
    ''', (PAGE_SIZE, comments_offset))
    comments = []
    for comment in comments_raw:
        comment_dict = dict(comment)
        _, score = moderate_content(comment_dict['content'])
        author_created_dt = comment_dict['user_created_at']
        author_age_days = (datetime.utcnow() - author_created_dt).days
        if author_age_days < 7:
            score *= 1.5
        risk_label, risk_sort_key = get_risk_profile(score)
        comment_dict['risk_label'] = risk_label
        comment_dict['risk_sort_key'] = risk_sort_key
        comment_dict['risk_score'] = round(score, 2)
        comments.append(comment_dict)

    comments.sort(key=lambda x: x['risk_score'], reverse=True) # Sort after fetching and scoring


    return render_template('admin.html.j2', 
                           users=users, 
                           posts=posts, 
                           comments=comments,
                           
                           # Pagination for Users
                           users_page=users_page,
                           total_users_pages=total_users_pages,
                           users_has_next=(users_page < total_users_pages),
                           users_has_prev=(users_page > 1),

                           # Pagination for Posts
                           posts_page=posts_page,
                           total_posts_pages=total_posts_pages,
                           posts_has_next=(posts_page < total_posts_pages),
                           posts_has_prev=(posts_page > 1),

                           # Pagination for Comments
                           comments_page=comments_page,
                           total_comments_pages=total_comments_pages,
                           comments_has_next=(comments_page < total_comments_pages),
                           comments_has_prev=(comments_page > 1),

                           current_tab=current_tab,
                           PAGE_SIZE=PAGE_SIZE)



@app.route('/admin/delete/user/<int:user_id>', methods=['POST'])
def admin_delete_user(user_id):
    if session.get('username') != 'admin':
        flash("You do not have permission to perform this action.", "danger")
        return redirect(url_for('feed'))
        
    if user_id == session.get('user_id'):
        flash('You cannot delete your own account from the admin panel.', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    db = get_db()
    db.execute('DELETE FROM users WHERE id = ?', (user_id,))
    db.commit()
    flash(f'User {user_id} and all their content has been deleted.', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/delete/post/<int:post_id>', methods=['POST'])
def admin_delete_post(post_id):
    if session.get('username') != 'admin':
        flash("You do not have permission to perform this action.", "danger")
        return redirect(url_for('feed'))

    db = get_db()
    db.execute('DELETE FROM comments WHERE post_id = ?', (post_id,))
    db.execute('DELETE FROM reactions WHERE post_id = ?', (post_id,))
    db.execute('DELETE FROM posts WHERE id = ?', (post_id,))
    db.commit()
    flash(f'Post {post_id} has been deleted.', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/delete/comment/<int:comment_id>', methods=['POST'])
def admin_delete_comment(comment_id):
    if session.get('username') != 'admin':
        flash("You do not have permission to perform this action.", "danger")
        return redirect(url_for('feed'))

    db = get_db()
    db.execute('DELETE FROM comments WHERE id = ?', (comment_id,))
    db.commit()
    flash(f'Comment {comment_id} has been deleted.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/rules')
def rules():
    return render_template('rules.html.j2')

@app.template_global()
def loop_color(user_id):
    # Generate a pastel color based on user_id hash
    h = hashlib.md5(str(user_id).encode()).hexdigest()
    r = int(h[0:2], 16)
    g = int(h[2:4], 16)
    b = int(h[4:6], 16)
    return f'rgb({r % 128 + 80}, {g % 128 + 80}, {b % 128 + 80})'



# ----- Functions to be implemented are below

# Task 3.3
def recommend(user_id, filter_following):
    print(f"\n=== DEBUG RECOMMEND ===")
    print(f"user_id: {user_id}")
    print(f"filter_following: {filter_following}")
    
    # -- fallback for logged-out users
    if not user_id:
        print("FALLBACK: Logged-out user")
        return query_db("""
            SELECT p.id, p.content, p.created_at, u.username, u.id AS user_id
            FROM posts p
            JOIN users u ON u.id = p.user_id
            LEFT JOIN (SELECT post_id, COUNT(*) AS total_reactions FROM reactions GROUP BY post_id) r
                   ON r.post_id = p.id
            ORDER BY IFNULL(r.total_reactions,0) DESC, p.created_at DESC
            LIMIT 5
        """)

    # -- 1) build interest profile
    positive = ('like', 'love', 'laugh', 'wow')
    liked = query_db(f"""
        SELECT p.id, p.content
        FROM posts p
        JOIN reactions r ON r.post_id = p.id
        WHERE r.user_id = ? AND r.reaction_type IN ({','.join('?'*len(positive))})
    """, (user_id, *positive)) or []
    
    print(f"Liked posts count: {len(liked)}")

    # -- social: who the user follows
    follow_rows = query_db('SELECT followed_id FROM follows WHERE follower_id = ?', (user_id,)) or []
    followed_ids = {row['followed_id'] for row in follow_rows}
    print(f"Following count: {len(followed_ids)}")

    # -- stop-words and keyword extraction
    stop = {
        'a','an','the','in','on','is','it','to','for','of','and','with','this','that','by','as','be','are','was','were',
        'from','or','at','i','you','we','they','he','she','them','his','her','our','your'
    }
    counts = collections.Counter()
    for row in liked:
        words = re.findall(r'\b\w+\b', (row['content'] or "").lower())
        for w in words:
            if len(w) > 2 and w not in stop and not w.isdigit():
                counts[w] += 1
    interest_terms = [w for w, _ in counts.most_common(12)]
    print(f"Interest keywords: {interest_terms}")

    # -- 2) gather candidates
    reacted_rows = query_db('SELECT post_id FROM reactions WHERE user_id = ?', (user_id,)) or []
    already_seen = {r['post_id'] for r in reacted_rows}
    print(f"Already reacted to: {len(already_seen)} posts")

    where = ["p.user_id != ?"]
    params = [user_id]

    if already_seen:
        placeholders = ",".join(["?"] * len(already_seen))
        where.append(f"p.id NOT IN ({placeholders})")
        params.extend(list(already_seen))

    if filter_following:
        if not followed_ids:
            print("FALLBACK: Filter following but no follows")
            return []
        placeholders = ",".join(["?"] * len(followed_ids))
        where.append(f"p.user_id IN ({placeholders})")
        params.extend(list(followed_ids))

    base_query = f"""
        SELECT p.id, p.content, p.created_at, u.username, u.id AS user_id,
               IFNULL(rx.total_reactions,0) AS total_reactions
        FROM posts p
        JOIN users u ON u.id = p.user_id
        LEFT JOIN (SELECT post_id, COUNT(*) AS total_reactions FROM reactions GROUP BY post_id) rx
               ON rx.post_id = p.id
        WHERE {' AND '.join(where)}
        ORDER BY p.created_at DESC
        LIMIT 200
    """
    candidates = query_db(base_query, tuple(params)) or []
    print(f"Candidates found: {len(candidates)}")

    # -- cold-start fallback
    if not interest_terms and not followed_ids:
        print("FALLBACK: Cold start (no interests, no follows)")
        return query_db("""
            SELECT p.id, p.content, p.created_at, u.username, u.id AS user_id
            FROM posts p
            JOIN users u ON u.id = p.user_id
            LEFT JOIN (SELECT post_id, COUNT(*) AS total_reactions FROM reactions GROUP BY post_id) r
                   ON r.post_id = p.id
            WHERE p.user_id != ?
            ORDER BY IFNULL(r.total_reactions,0) DESC, p.created_at DESC
            LIMIT 5
        """, (user_id,))

    # -- 3) score candidates
    def score_row(row):
        text = (row['content'] or "").lower()
        hits = 0
        for t in interest_terms:
            if t in text:
                hits += 1
        content_score = 2.0 * hits
        social_score = 1.5 if row['user_id'] in followed_ids else 0.0
        pop = row['total_reactions']
        if pop >= 15: pop_score = 0.7
        elif pop >= 7: pop_score = 0.5
        elif pop >= 3: pop_score = 0.3
        else: pop_score = 0.0
        return content_score + social_score + pop_score

    scored = []
    for row in candidates:
        s = score_row(row)
        if s <= 0 and not filter_following and row['total_reactions'] >= 3:
            s = 0.6
        scored.append((s, row))

    scored.sort(key=lambda x: (x[0], x[1]['created_at']), reverse=True)
    print(f"Top 5 scores: {[s[0] for s in scored[:5]]}")

    # -- 4) prepare final list
    out = []
    for _, row in scored[:5]:
        clean, _ = moderate_content(row['content'])
        out.append({
            'id': row['id'],
            'content': clean,
            'created_at': row['created_at'],
            'username': row['username'],
            'user_id': row['user_id']
        })

    # -- last-chance fallback
    if not out:
        print("FALLBACK: Empty results, returning recent posts")
        return query_db("""
            SELECT p.id, p.content, p.created_at, u.username, u.id AS user_id
            FROM posts p
            JOIN users u ON u.id = p.user_id
            ORDER BY p.created_at DESC
            LIMIT 5
        """)

    print(f"Returning {len(out)} recommendations")
    print("\nRecommended Posts:")
    for i, post in enumerate(out, 1):
        content_preview = post['content'][:80] + "..." if len(post['content']) > 80 else post['content']
        print(f"  {i}. Post ID: {post['id']} | Author: @{post['username']} | Content: {content_preview}")
    print("======================\n")
    return out
    

# Task 3.2
def user_risk_analysis(user_id):
    # -- helper: safely parse timestamps
    def parse_ts(ts):
        if not ts:
            return None
        if isinstance(ts, datetime):
            return ts
        for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%d'):
            try:
                return datetime.strptime(ts, fmt)
            except ValueError:
                continue
        return None

    # -- fetch user record
    user = query_db('SELECT id, profile, created_at FROM users WHERE id = ?', (user_id,), one=True)
    if not user:
        return 0.0

    now = datetime.now(timezone.utc)

    # -- step 1: profile_score
    profile_text = user['profile'] or ""
    _, profile_score = moderate_content(profile_text)

    # -- step 2: average_post_score
    posts = query_db('SELECT content, created_at FROM posts WHERE user_id = ?', (user_id,)) or []
    post_scores = [moderate_content(p['content'] or "")[1] for p in posts]
    average_post_score = sum(post_scores) / len(post_scores) if post_scores else 0.0

    # -- step 3: average_comment_score
    comments = query_db('SELECT content, created_at FROM comments WHERE user_id = ?', (user_id,)) or []
    comment_scores = [moderate_content(c['content'] or "")[1] for c in comments]
    average_comment_score = sum(comment_scores) / len(comment_scores) if comment_scores else 0.0

    # -- step 4: combine scores
    content_risk_score = (profile_score * 1.0) + (average_post_score * 3.0) + (average_comment_score * 1.0)

    # -- step 5: apply account-age multiplier
    created_at = parse_ts(user['created_at'])
    if created_at:
        account_age_days = (now - created_at.replace(tzinfo=timezone.utc)).days
    else:
        account_age_days = 999999

    if account_age_days < 7:
        user_risk_score = content_risk_score * 1.5
    elif account_age_days < 30:
        user_risk_score = content_risk_score * 1.2
    else:
        user_risk_score = content_risk_score

    # -- extra rule: toxic engagement (+0.5 if >30% of comments on user's posts are moderated)
    user_posts = query_db('SELECT id FROM posts WHERE user_id = ?', (user_id,)) or []
    total_comments = 0
    moderated_comments = 0

    for post in user_posts:
        rows = query_db('SELECT content FROM comments WHERE post_id = ?', (post['id'],)) or []
        for r in rows:
            _, s = moderate_content(r['content'] or "")
            total_comments += 1
            if s >= 2.0:
                moderated_comments += 1

    if total_comments > 0:
        moderation_ratio = moderated_comments / total_comments
        if moderation_ratio > 0.30:
            user_risk_score += 0.5

    print(f"\nUser {user_id}\nProfile Score: {profile_score}\nAvg Post Score: {average_post_score}\nAvg Comment Score: {average_comment_score}\nContent Risk: {content_risk_score}\nAccount Age Days: {account_age_days}\nFinal Risk Score: {user_risk_score}")
    # -- step 6: final cap
    return min(5.0, round(user_risk_score, 2))

# Task 3.1
def moderate_content(content):
    if not isinstance(content, str) or not content:
        return "", 0.0

    text = content

    # -- stage 1.1: fixed scoring as 5.0

    # -- 1.1.1: tier1 words (whole-word, immediate removal)
    if TIER1_WORDS:
        pattern_t1 = r"\b(" + "|".join(map(re.escape, TIER1_WORDS)) + r")\b"
        if re.search(pattern_t1, text, flags=re.IGNORECASE):
            return "[content removed due to severe violation]", 5.0

    # -- 1.1.2: tier2 phrases (whole-phrase, immediate removal)
    for phrase in TIER2_PHRASES or []:
        if re.search(re.escape(phrase), text, flags=re.IGNORECASE):
            return "[content removed due to spam/scam policy]", 5.0

    # -- stage 1.2: incremental scoring begins at 0.0
    score = 0.0

    # -- 1.2.1: tier3 words (+2 each, censor with asterisks)
    if TIER3_WORDS:
        pattern_t3 = r"\b(" + "|".join(map(re.escape, TIER3_WORDS)) + r")\b"
        t3_matches = re.findall(pattern_t3, text, flags=re.IGNORECASE)
        score += 2.0 * len(t3_matches)
        text = re.sub(pattern_t3, lambda m: "*" * len(m.group(0)), text, flags=re.IGNORECASE)

    # -- 1.2.2: external links (+2 each, replace)
    url_pattern = r"(https?://[^\s]+)"
    urls = re.findall(url_pattern, text)
    if urls:
        score += 2.0 * len(urls)
        text = re.sub(url_pattern, "[link removed]", text)

    # -- 1.2.3: excessive capitalization (+0.5 fixed)
    letters = [c for c in text if c.isalpha()]
    if len(letters) > 15:
        upper_ratio = sum(1 for c in letters if c.isupper()) / len(letters)
        if upper_ratio > 0.7: # threshold 70%
            score += 0.5

    # -- 1.2.4 (extra rule - my proposal): private info disclosure (+2 each, replace)
    hits = 0
    valid_emails = []
    valid_phones = []

    # emails: find, validate, and count occurrences
    email_re = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,20}\b"
    for candidate in re.findall(email_re, text):
        try:
            validate_email(candidate)
            valid_emails.append(candidate)
            hits += 1
        except EmailNotValidError:
            pass

    # phonenumbers: match, validate, and count occurrences
    for match in phonenumbers.PhoneNumberMatcher(text, None):
        if phonenumbers.is_valid_number(match.number):
            valid_phones.append(match.raw_string)
            hits += 1

    # replace all validated emails and phones with placeholder
    if valid_emails:
        email_pattern = r"|".join(map(re.escape, set(valid_emails)))
        text = re.sub(email_pattern, "[private info removed]", text)

    if valid_phones:
        phone_pattern = r"|".join(map(re.escape, set(valid_phones)))
        text = re.sub(phone_pattern, "[private info removed]", text)

    if hits:
        score += 2.0 * hits

    return text.strip(), round(score, 2)

if __name__ == '__main__':
    # sample_text = "faggot gmail@email.com gmail@email.com +358449525811"
    # cleaned, score = moderate_content(sample_text)
    # print("\nOriginal:", sample_text)
    # print("Cleaned:", cleaned)
    # print("Score:", score)

    # print('\n-------------TIER1_WORDS-------------')
    # print(TIER1_WORDS)
    # print('\n-------------TIER2_PHRASES-------------')
    # print(TIER2_PHRASES)
    # print('\n-------------TIER3_WORDS-------------')
    # print(TIER3_WORDS)

    # print('\n========== Exercise 3.2: User Risk Analysis ==========\n')
    
    # with app.app_context():
        # all_users = query_db('SELECT id, username FROM users ORDER BY id')
        
        # user_risks = []
        
        # print("Calculating risk scores...\n")
        # test_user_ids = [11, 13, 66, 68, 541]

        # for user in all_users:
        #     if user['id'] in test_user_ids:
        #         risk = user_risk_analysis(user['id'])
        #         user_risks.append({
        #             'id': user['id'],
        #             'username': user['username'],
        #             'score': risk
        #         })
        
        # user_risks.sort(key=lambda x: x['score'], reverse=True)
        
        # print("\n\n===== Top 5 Highest Risk Users =====\n")
        # print(f"{'Rank':<8}{'User ID':<12}{'Username':<25}{'Score':<12}{'Level'}")
        # print("-" * 70)
        
        # for i, u in enumerate(user_risks[:5], 1):
        #     if u['score'] >= 5.0:
        #         level = "HIGH"
        #     elif u['score'] >= 3.0:
        #         level = "MEDIUM"
        #     elif u['score'] >= 1.0:
        #         level = "LOW"
        #     else:
        #         level = "NONE"
            
        #     print(f"{i:<8}{u['id']:<12}{u['username']:<25}{u['score']:<12.2f}{level}")
        
        # print("\n\n===== Test Cases =====\n")
        
        # for uid in test_user_ids:
        #     found = next((u for u in user_risks if u['id'] == uid), None)
        #     if found:
        #         if found['score'] >= 5.0:
        #             level = "HIGH"
        #         elif found['score'] >= 3.0:
        #             level = "MEDIUM"
        #         elif found['score'] >= 1.0:
        #             level = "LOW"
        #         else:
        #             level = "NONE"
        #         print(f"User {uid} (@{found['username']}): Score = {found['score']:.2f}, Level = {level}")
        #     else:
        #         print(f"User {uid}: NOT FOUND")
        
        # print("\n" + "="*70 + "\n")

    # print('\n\n========== Exercise 3.3: Recommendation Algorithm ==========\n')

    # with app.app_context():
    #     # Test Case 1: User with interests
    #     test_user_id = 10  # Change to a user who has liked posts
    #     print(f"Testing recommendations for User ID: {test_user_id}\n")
        
    #     # Get user's liked posts to show their interests
    #     liked = query_db("""
    #         SELECT p.content 
    #         FROM posts p
    #         JOIN reactions r ON r.post_id = p.id
    #         WHERE r.user_id = ? AND r.reaction_type IN ('like', 'love', 'laugh', 'wow')
    #         LIMIT 3
    #     """, (test_user_id,))
        
    #     print("User's liked posts (showing interests):")
    #     for i, post in enumerate(liked, 1):
    #         content = post['content'][:100] + "..." if len(post['content']) > 100 else post['content']
    #         print(f"  {i}. {content}")
        
    #     # Get recommendations
    #     recommendations = recommend(test_user_id, False)
        
    #     print(f"\nRecommended Posts (Total: {len(recommendations)}):\n")
    #     print(f"{'Rank':<8}{'Post ID':<12}{'Author':<20}{'Content Preview'}")
    #     print("-" * 80)
        
    #     for i, rec in enumerate(recommendations, 1):
    #         content = rec['content'][:50] + "..." if len(rec['content']) > 50 else rec['content']
    #         print(f"{i:<8}{rec['id']:<12}{rec['username']:<20}{content}")
        
    #     # Test Case 2: Cold start user
    #     print("\n\nTest Case 2: Cold Start User (No interactions)")
    #     cold_start_recs = recommend(999999, False)  # Non-existent user
    #     print(f"Fallback recommendations: {len(cold_start_recs)} posts returned")
        
    #     # Test Case 3: Logged out user
    #     print("\nTest Case 3: Logged Out User")
    #     logged_out_recs = recommend(None, False)
    #     print(f"Popular posts for logged-out user: {len(logged_out_recs)} posts returned")
        
    #     print("\n" + "="*80 + "\n")

    app.run(debug=True, port=8080)

