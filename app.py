import os
import mysql.connector
from flask import Flask, session, redirect, request, render_template, flash, abort,jsonify,url_for
from werkzeug.security import generate_password_hash, check_password_hash
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
import google.auth.transport.requests
import requests
import pandas as pd
import re
import pickle
from flask import Flask, request, jsonify
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.tree import DecisionTreeRegressor
from sklearn.model_selection import train_test_split
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import request, session, redirect, jsonify
from bs4 import BeautifulSoup


app = Flask("Google Login App")
app.secret_key = "vijay"
RENDER_APP_NAME = os.environ.get("RENDER_APP_NAME")
RENDER_APP_URL = f"https://{RENDER_APP_NAME}.onrender.com"
REDIRECT_URI = f"{RENDER_APP_URL}/callback"

# MySQL connection details
MYSQL_HOST = os.environ.get("MYSQL_HOST")
MYSQL_PORT = os.environ.get("MYSQL_PORT")
MYSQL_USER = os.environ.get("MYSQL_USER")  # replace with your MySQL username
MYSQL_PASSWORD = os.environ.get("MYSQL_PASSWORD")  # replace with your MySQL password
MYSQL_DB = os.environ.get("MYSQL_DB")  # replace with your MySQL database name

# Google OAuth details
GOOGLE_CLIENT_ID = "282021514569-pdsnov6vqp2cegkj271cvdcs87ogj4q5.apps.googleusercontent.com"
client_secrets_file = os.path.join(os.path.dirname(__file__), "client_secret.json")

# OAuth flow setup
flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri=f"{RENDER_APP_URL}/callback"
)

# Allow insecure transport (only for local development)
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

# Establish MySQL connection
def get_db_connection():
    connection = mysql.connector.connect(host=MYSQL_HOST,
                                         user=MYSQL_USER,
                                         password=MYSQL_PASSWORD,
                                         database=MYSQL_DB,
                                         port=MYSQL_PORT)
    return connection


# Function to create the necessary tables if they don't exist
def create_tables():
    connection = get_db_connection()
    cursor = connection.cursor()

    # Create google_users table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS google_users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        first_name VARCHAR(50),
        last_name VARCHAR(50),
        email VARCHAR(100) UNIQUE,
        google_id VARCHAR(255) UNIQUE
    );
    """)

    # Create traditional_users table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS traditional_users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        first_name VARCHAR(50),
        last_name VARCHAR(50),
        email VARCHAR(100) UNIQUE,
        password VARCHAR(255)
    );
    """)

    cursor.execute("""CREATE TABLE IF NOT EXISTS userfeedback (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_name VARCHAR(100) NOT NULL,
    rating INT NOT NULL,
    feedback TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);""")

    cursor.execute("""CREATE TABLE IF NOT EXISTS bookmarked_places (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_name VARCHAR(200) NOT NULL,
    node_name VARCHAR(200) NOT NULL,
    image_url VARCHAR(255) NOT NULL
); """)

    cursor.execute("""CREATE TABLE IF NOT EXISTS placefeedback (
    user_name VARCHAR(255) NOT NULL,
    attraction_name VARCHAR(255) NOT NULL,
    feedback TEXT NOT NULL,
    rating INT NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
""")

    connection.commit()
    connection.close()

# Check if the email is already registered in traditional_users table
def is_email_registered_traditional(email):
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    cursor.execute("SELECT * FROM traditional_users WHERE email = %s", (email,))
    user = cursor.fetchone()
    connection.close()
    return user is not None

# Check if the email is already registered in google_users table
def is_email_registered_google(email):
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    cursor.execute("SELECT * FROM google_users WHERE email = %s", (email,))
    user = cursor.fetchone()
    connection.close()
    return user is not None

# Login required decorator (for routes that require login)
def login_is_required(function):
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            return abort(401)  # Authorization required

        else:
            return function()
    return wrapper

@app.route("/login", methods=["POST"])
def login():
    email = request.form["email"]
    password = request.form["password"]

    # Check if the email exists in traditional users table
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    cursor.execute("SELECT * FROM traditional_users WHERE email = %s", (email,))
    user = cursor.fetchone()

    if user:
        # Check if the password matches
        stored_password = user["password"]
        if check_password_hash(stored_password, password):
            session["google_id"] = None  # Ensure Google login doesn't interfere
            session["name"] = user["first_name"]
            flash("Login successful!", "success")
            return redirect("/protected_area")
        else:
            flash("Invalid password.", "danger")
    else:
        flash("Email not found.", "danger")

    connection.close()
    return redirect("/")  # Redirect back to login form or home page

@app.route("/register", methods=["POST"])
def register():
    first_name = request.form["first_name"]
    last_name = request.form["last_name"]
    email = request.form["email"]
    password = request.form["password"]

    # Check if the email already exists in traditional_users table
    if is_email_registered_traditional(email):
        flash("Email is already registered, please choose another one.", "danger")
        return redirect("/")  # Redirect back to the home page or registration form

    # Hash the password before storing it
    hashed_password = generate_password_hash(password)

    # Insert new user into the traditional_users table
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute(
        "INSERT INTO traditional_users (first_name, last_name, email, password) VALUES (%s, %s, %s, %s)",
        (first_name, last_name, email, hashed_password)
    )
    connection.commit()
    connection.close()

    flash("Registration successful. You can now log in.", "success")
    return render_template("dashboard.html", name=first_name)


@app.route('/submit_feedback', methods=['POST'])
def submit_feedback():
    # Create the feedback table if it doesn't exist
    create_tables()

    if request.method == 'POST':
        # Get user ID and user name from session

        user_name = session.get('name')  # Assuming user_name is stored in session

        # Ensure the user is logged in (check if user_id exists in the session)
        if not user_name:
            return redirect('/login')  # Redirect to login page if not logged in

        attraction_name = request.form['attraction_name']  # Get the attraction name from the form
        feedback = request.form['feedback']
        rating = request.form['rating']

        # Insert feedback into the database
        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute("""
            INSERT INTO placefeedback (user_name, attraction_name, feedback, rating)
            VALUES (%s, %s, %s, %s)
        """, (user_name, attraction_name, feedback, rating))

        connection.commit()
        cursor.close()
        connection.close()

        return jsonify({"message": "Feedback submitted successfully!"}), 200
@app.route("/login_with_google")
def login_with_google():
    # Initiates the Google login process
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)

@app.route("/callback")
def callback():
    flow.fetch_token(authorization_response=request.url)

    # Check if state matches
    if not session["state"] == request.args["state"]:
        abort(500)  # State mismatch!

    credentials = flow.credentials
    request_session = requests.session()
    token_request = google.auth.transport.requests.Request(session=request_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )

    google_id = id_info.get("sub")
    name = id_info.get("name")
    email = id_info.get("email")

    # Check if the email is already registered in the google_users table
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    cursor.execute("SELECT * FROM google_users WHERE google_id = %s OR email = %s", (google_id, email))
    user = cursor.fetchone()

    if user is None:
        # User doesn't exist, so register them with Google login details
        first_name, last_name = name.split(" ", 1) if " " in name else (name, "")
        cursor.execute(
            "INSERT INTO google_users (first_name, last_name, email, google_id) VALUES (%s, %s, %s, %s)",
            (first_name, last_name, email, google_id)
        )
        connection.commit()
        session["name"] = first_name  # Store the name in the session
        flash("Google login successful! Account created.", "success")
    else:
        # User already exists, so just log them in
        session["name"] = user["first_name"]
        flash("Google login successful!", "success")

    session["google_id"] = google_id
    connection.close()

    return redirect("/protected_area")

@app.route("/logout")
def logout():
    session.clear()  # Clears session data
    return redirect("/")  # Redirect to home page

@app.route("/")
def index():
    return render_template("newhomepage.html")

@app.route("/protected_area")
@login_is_required
def protected_area():
    return render_template("dashboard.html", name=session['name'])

@app.route('/bookmark', methods=['POST'])
def bookmark_place():
    # Get data from the request

    user_name = session.get('name')  # Assuming user_name is stored in session
    if not user_name:
            return redirect('/login')

    data = request.json

    node_name = data.get('node_name')
    image_url = data.get('image_url')

    if not node_name or not image_url:
        return jsonify({"message": "Missing data"}), 400

    # Save to the database using MySQL Connector
    connection = get_db_connection()
    cursor = connection.cursor()

    #



    # Insert data into the 'bookmarked_places' table
    # Step 1: Check if the combination already exists in the database
    cursor.execute(
    "SELECT COUNT(*) FROM bookmarked_places WHERE user_name = %s AND node_name = %s AND image_url = %s", 
    (user_name, node_name, image_url)
    )

    # Step 2: Fetch the result
    result = cursor.fetchone()

    # Step 3: If the result is 0, then it's safe to insert, otherwise skip
    if result[0] == 0:
        cursor.execute(
        "INSERT INTO bookmarked_places (user_name, node_name, image_url) VALUES (%s, %s, %s)", 
        (user_name, node_name, image_url)
        )

    connection.commit()

    cursor.close()
    connection.close()

    return jsonify({"message": "Bookmark saved successfully!"}), 201


@app.route('/delete-bookmark', methods=['POST'])
def delete_bookmark():
    user_name = session.get('name')  # Assuming the user_name is stored in session
    if not user_name:
        return redirect('/login')  # Redirect to login if not logged in

    # Get the data from the request (node_name and image_url)
    data = request.get_json()  # Get the JSON body of the request
    node_name = data.get('node_name')
    image_url = data.get('image_url')

    # Validate if both node_name and image_url are provided
    if not node_name or not image_url:
        return jsonify({"message": "Both node_name and image_url must be provided"}), 400

    # Connect to the database
    connection = get_db_connection()
    cursor = connection.cursor()

    # Check if the bookmark exists for the given user and node_name
    cursor.execute(
        "SELECT * FROM bookmarked_places WHERE node_name = %s AND user_name = %s", 
        (node_name, user_name)
    )

    # Consume any unread result to avoid the 'Unread result found' error
    cursor.fetchall()  # Consume the result set

    # Now perform the delete query
    cursor.execute(
        "DELETE FROM bookmarked_places WHERE node_name = %s AND user_name = %s", 
        (node_name, user_name)
    )
    connection.commit()  # Commit the transaction to delete the bookmark

    cursor.close()
    connection.close()

    return jsonify({"message": "Bookmark deleted successfully!"}), 200

@app.route('/userfeedback')
def userfeedback():
    return render_template('userfeedback.html')

@app.route('/submituser-feedback', methods=['POST'])

def submituser_feedback():
    # Get feedback data from the request
    data = request.get_json()

    if data:
        user_name = session.get('name')  # Assuming the user name is stored in session

        if not user_name:
            return redirect('/login')  # Redirect to login page if the user is not logged in

        feedback = data.get('feedback')
        rating = data.get('rating')

        try:
            # Insert feedback into the database
            connection = get_db_connection()
            cursor = connection.cursor()

            cursor.execute("""
                INSERT INTO userfeedback (user_name, feedback, rating)
                VALUES (%s, %s, %s)
            """, (user_name, feedback, rating))

            connection.commit()
            cursor.close()
            connection.close()

            # Only send email if the feedback was successfully submitted
            send_email(
                recipient='gajulavamsi87@gmail.com',
                subject='New Feedback Submitted',
                message_body=f"User: {user_name}\nFeedback: {feedback}\nRating: {rating}"
            )

            # Respond back with a success message
            return jsonify({"message": "Feedback submitted successfully"}), 200

        except Exception as e:
            # Handle database errors
            print(f"Failed to submit feedback. Error: {e}")
            return jsonify({"error": "Failed to submit feedback."}), 500
    else:
        return jsonify({"error": "Invalid request data."}), 400


def send_email(
    recipient='gajulavamsi87@gmail.com',  # Default recipient 
    subject='Default Subject',  # Default subject
    message_body='This is a default message.'  # Default message body
):
    SMTP_SERVER = os.environ.get("SMTP_SERVER")  # For Gmail SMTP
    SMTP_PORT = os.environ.get("SMTP_PORT")
    EMAIL_ADDRESS = os.environ.get("EMAIL_ADDRESS")  # Your email
    EMAIL_PASSWORD = os.environ.get("EMAIL_PASSWORD")  # Your app password

    try:
        # Create Email
        msg = MIMEMultipart()
        msg['From'] = EMAIL_ADDRESS
        msg['To'] = recipient
        msg['Subject'] = subject
        msg.attach(MIMEText(message_body, 'plain'))

        # Send Email
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()  # Secure the connection
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            server.send_message(msg)

        print("Email sent successfully!")
    except Exception as e:
        print(f"Failed to send email. Error: {e}")





@app.route('/admin-feedback', methods=['GET'])
def admin_feedback():
    # Connect to your database
    connection = get_db_connection()
    cursor = connection.cursor()

    # Fetch all feedbacks
    cursor.execute("SELECT user_name, rating, feedback, created_at FROM userfeedback ORDER BY created_at DESC")
    feedbacks = cursor.fetchall()

    # Close connection
    cursor.close()
    connection.close()

    return render_template('admin_feedback.html', feedbacks=feedbacks)


@app.route('/view-bookmarks')
def view_bookmarks():
    # Get the username from the session (assuming it's stored during login)
    user_name = session.get('name')
    if not user_name:
        return redirect('/login')  # If user is not logged in, redirect to login page

    # Connect to the database
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    # Fetch all bookmarked places for the logged-in user
    cursor.execute("SELECT node_name, image_url FROM bookmarked_places WHERE user_name = %s", (user_name,))
    bookmarks = cursor.fetchall()

    cursor.close()
    connection.close()

    # Render the bookmarks on the front-end
    return render_template('bookmarks.html', bookmarks=bookmarks)



@app.route('/chatwithAI')
def chat():
    return render_template('chat.html')

@app.route('/new')
def newhomepage():
    return render_template('newhomepage.html')


@app.route('/show_reviews', methods=['GET'])
def show_reviews():
    # Get the attraction name from the query parameter
    attraction_name = request.args.get('attraction_name', None)

    # Check if attraction_name is provided
    if not attraction_name:
        return "<h1>Error: Attraction name is required.</h1>", 400

    # Fetch reviews from the database
    try:
        # Connect to the database
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        # Query to fetch reviews for the given attraction name
        query = """
        SELECT user_name, feedback, rating, timestamp 
        FROM placefeedback 
        WHERE attraction_name = %s
        """
        cursor.execute(query, (attraction_name,))
        reviews = cursor.fetchall()

        connection.close()
    except mysql.connector.Error as err:
        return f"<h1>Database Error: {err}</h1>", 500

    # Render the reviews in a template
    return render_template('reviews.html', reviews=reviews, attraction_name=attraction_name)


MODEL_FILE = "backend/ml.pkl"

# Load the model
model = pickle.load(open(MODEL_FILE, 'rb'))

# Get the feature names from the model to ensure correct order of columns
feature_names = model.feature_names_in_

@app.route('/predict', methods=['POST'])
def predict():
    # Get form data from frontend
    from_date = request.form['From_Date']
    to_date = request.form['To_Date']
    from_place = request.form['From_Place']
    to_place = request.form['To_Place']
    no_of_person = int(request.form['No_of_Person'])
    vehicle_types = request.form['Vehicle_Types']

    # Prepare the data in the format expected by the model
    new_data = {
        'From_Date': from_date,
        'To_Date': to_date,
        'From_Place': from_place,
        'To_Place': to_place,
        'No_of_Person': no_of_person,
        'Vehicle_Types': vehicle_types
    }

    # Convert the data into a DataFrame
    new_df = pd.DataFrame([new_data])

    try:
        prediction = model.predict(new_df)
        predicted_cost = f'Rs. {prediction[0]}'
    except Exception as e:
        print(f"Error during prediction: {e}")
        return jsonify({'error': 'Prediction failed. Please check the input data or model configuration.'}), 500

    # Render the result page with input details and predicted cost
    return render_template('result.html', data=new_data, cost=predicted_cost)



@app.route("/out")
def out():
    return render_template("out.html")

@app.route('/dis/<dynamic_part>')
def dis(dynamic_part):
    # Capture the dynamic part of the URL
    current_url = request.url  # Full URL
    print(f"Current URL: {current_url}")

    # Send a GET request to the external API
    url = "https://jokerscript.xyz/api/ai.php"
    params = {'query': dynamic_part}
    response = requests.get(url, params=params)

    # Get the raw response as JSON
    try:
        json_response = response.json()  # Assuming the response is in JSON format
        # Extract the textContent from the JSON response
        raw_text = json_response.get('textContent', '')
    except ValueError:
        return "Error: Response is not in valid JSON format."

    # Print the raw response text for debugging
    print(f"Raw Text Content: {raw_text}")

    # 1. Clean the response content:
    # Remove ** and format bullet points or other formatting
    cleaned_content = raw_text.replace('**', '')  # Remove '**' characters from the response

    # 2. Replace \n\n (double newlines) with <br><br> (HTML line break)
    cleaned_content = re.sub(r'\n\n', '<br><br>', cleaned_content)  # Double newlines to <br><br>

    # 3. Replace single newlines with <br> (HTML line break)
    cleaned_content = cleaned_content.replace('\n', ' ')  # Single newlines to spaces

    # 4. Replace '*' with <ul><li> for bullet points in lists
    cleaned_content = re.sub(r'\*', '<ul><li>', cleaned_content)  # Replace '*' with <ul><li>
    cleaned_content = re.sub(r'(<li>.*?<\/li>)\s*<\/ul>', r'\1</ul>', cleaned_content)  # Correct closing </ul> tag issue

    # 5. Remove any unwanted HTML tags (if necessary)
    cleaned_content = re.sub(r'</?[^>]+(>|$)', '', cleaned_content)  # Remove HTML tags

    # 6. Optional: Use BeautifulSoup to remove any leftover HTML tags and clean text
    soup = BeautifulSoup(cleaned_content, 'html.parser')
    clean_text = soup.get_text(separator=' ', strip=True)  # Clean text without tags

    # 7. Format the final cleaned text (replace escaped characters if any)
    clean_text = clean_text.replace(r'\\n', '<br>')  # Convert newline escape sequence to <br>

    # Return the cleaned and formatted content in a template
    if clean_text:
        return render_template('dis.html', place_name=dynamic_part, data=clean_text)
    else:
        return "No valid script content found in the response."





# Result route
@app.route('/result')
def result():
    cost = request.args.get('cost', "Error")
    return render_template('package.html', cost=cost)



create_tables()  


 