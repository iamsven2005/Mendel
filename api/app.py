from datetime import date
from flask import Flask, url_for, render_template, request, session, redirect
from flask_session import Session
from functools import wraps
import os
from dotenv import load_dotenv
import psycopg2
from kinde_sdk import Configuration, ApiException
from kinde_sdk.kinde_api_client import GrantType, KindeApiClient
from kinde_sdk.apis.tags import users_api
from kinde_sdk.model.user import User
import resend

CONTACT_EMAIL = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>New Message Notification</title>
</head>
<body>
    <h2>New Message Received!</h2>
    <p><strong>Name:</strong> {name}</p>
    <p><strong>Email:</strong> {email}</p>
    <p><strong>Message:</strong></p>
    <blockquote>
        {message}
    </blockquote>
</body>
</html>
"""

CREATE_TABLE_SQL = """
    CREATE TABLE IF NOT EXISTS rooms (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL
    )
"""
load_dotenv()  # Load environment variables from .env file
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL")
url = os.getenv("DATABASE_URL")
connection = psycopg2.connect(url)


app = Flask(__name__)


app.config["ADMIN_EMAIL"] = os.getenv("ADMIN_EMAIL")
app.config["LOGOUT_REDIRECT_URL"] = os.getenv("LOGOUT_REDIRECT_URL")
app.config["KINDE_CALLBACK_URL"] = os.getenv("KINDE_CALLBACK_URL")
app.config["CLIENT_ID"] = os.getenv("CLIENT_ID")
app.config["CLIENT_SECRET"] = os.getenv("CLIENT_SECRET")
app.config["KINDE_ISSUER_URL"] = os.getenv("KINDE_ISSUER_URL")
app.config["GRANT_TYPE"] = os.getenv("GRANT_TYPE")
app.config["CODE_VERIFIER"] = os.getenv("CODE_VERIFIER")
app.config["TEMPLATES_AUTO_RELOAD"] = os.getenv("TEMPLATES_AUTO_RELOAD")
app.config["SESSION_TYPE"] = os.getenv("SESSION_TYPE")
app.config["SESSION_PERMANENT"] = os.getenv("SESSION_PERMANENT")
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
app.config["MGMT_API_CLIENT_ID"] = os.getenv("MGMT_API_CLIENT_ID")
app.config["MGMT_API_CLIENT_SECRET"] = os.getenv("MGMT_API_CLIENT_SECRET")
Session(app)

# Map the GRANT_TYPE string to the GrantType enum
grant_type_map = {
    "client_credentials": GrantType.CLIENT_CREDENTIALS,
    "authorization_code": GrantType.AUTHORIZATION_CODE,
    "authorization_code_with_pkce": GrantType.AUTHORIZATION_CODE_WITH_PKCE,
}

# Get the grant_type from the config and map it to the enum
grant_type = grant_type_map.get(app.config["GRANT_TYPE"].lower())
if not grant_type:
    raise ValueError("Invalid GRANT_TYPE provided")

configuration = Configuration(host=app.config["KINDE_ISSUER_URL"])
kinde_api_client_params = {
    "configuration": configuration,
    "domain": app.config["KINDE_ISSUER_URL"],
    "client_id": app.config["CLIENT_ID"],
    "client_secret": app.config["CLIENT_SECRET"],
    "grant_type": grant_type,
    "callback_url": app.config["KINDE_CALLBACK_URL"],
}
if grant_type == GrantType.AUTHORIZATION_CODE_WITH_PKCE:
    kinde_api_client_params["code_verifier"] = app.config["CODE_VERIFIER"]

kinde_client = KindeApiClient(**kinde_api_client_params)
user_clients = {}


def get_authorized_data(kinde_client):
    user = kinde_client.get_user_details()
    return {
        "id": user.get("id"),
        "user_given_name": user.get("given_name"),
        "user_family_name": user.get("family_name"),
        "user_email": user.get("email"),
        "user_picture": user.get("picture"),
    }


def login_required(user):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not user.is_authenticated():
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator
##ADD DB
@app.route("/1", methods=["GET"])
def create_room():
    with connection:
        with connection.cursor() as cursor:
            cursor.execute(CREATE_TABLE_SQL)
    return "Room table created successfully", 201


@app.route("/")
def index():
    data = {"current_year": date.today().year}
    template = "logged_out.html"
    if session.get("user"):
        kinde_client = user_clients.get(session.get("user"))
        if kinde_client and kinde_client.is_authenticated():
            data.update(get_authorized_data(kinde_client))        
            template = "home.html"
    return render_template(template, **data)


@app.route("/api/auth/login")
def login():
    return redirect(kinde_client.get_login_url())


@app.route("/api/auth/register")
def register():
    return redirect(kinde_client.get_register_url())


@app.route("/api/auth/kinde_callback")
def callback():
    kinde_client.fetch_token(authorization_response=request.url)
    data = {"current_year": date.today().year}
    data.update(get_authorized_data(kinde_client))
    session["user"] = data.get("id")
    user_clients[data.get("id")] = kinde_client
    return redirect(url_for("index"))


@app.route("/api/auth/logout")
def logout():
    user_clients[session.get("user")] = None
    session["user"] = None
    return redirect(
        kinde_client.logout(redirect_to=app.config["LOGOUT_REDIRECT_URL"])
    )


@app.route("/details")
def get_details():
    template = "logged_out.html"
    data = {"current_year": date.today().year}

    if session.get("user"):
        kinde_client = user_clients.get(session.get("user"))

        if kinde_client:
            data = {"current_year": date.today().year}
            data.update(get_authorized_data(kinde_client))
            data["access_token"] = kinde_client.configuration.access_token
            template = "details.html"

    return render_template(template, **data)


@app.route("/helpers")
def get_helper_functions():
    template = "logged_out.html"

    if session.get("user"):
        kinde_client = user_clients.get(session.get("user"))
        data = {"current_year": date.today().year}

        if kinde_client:
            data.update(get_authorized_data(kinde_client))
            #print(kinde_client.configuration.access_token)
            data["claim"] = kinde_client.get_claim("iss")
            data["organization"] = kinde_client.get_organization()
            data["user_organizations"] = kinde_client.get_user_organizations()
            data["flag"] = kinde_client.get_flag("theme","red")
            data["bool_flag"] = kinde_client.get_boolean_flag("is_dark_mode",False)
            data["str_flag"] = kinde_client.get_string_flag("theme","red")
            data["int_flag"] = kinde_client.get_integer_flag("competitions_limit",10)
            template = "helpers.html"



        else:
            template = "logged_out.html"

    return render_template(template, **data)

@app.route("/api_demo")
def get_api_demo():
    template = "api_demo.html"

    if session.get("user"):
        kinde_client = user_clients.get(session.get("user"))
        data = {"current_year": date.today().year}

        if kinde_client:
            data.update(get_authorized_data(kinde_client))

            try:
                kinde_mgmt_api_client = KindeApiClient(
                    configuration=configuration,
                    domain=app.config["KINDE_ISSUER_URL"],
                    client_id=app.config["MGMT_API_CLIENT_ID"],
                    client_secret=app.config["MGMT_API_CLIENT_SECRET"],
                    audience=f"{app.config['KINDE_ISSUER_URL']}/api",
                    callback_url=app.config["KINDE_CALLBACK_URL"],
                    grant_type=GrantType.CLIENT_CREDENTIALS,
                )

                api_instance = users_api.UsersApi(kinde_mgmt_api_client)
                api_response = api_instance.get_users()
                data['users'] = [
                    {
                        'first_name': user.get('first_name', ''),
                        'last_name': user.get('last_name', ''),
                        'total_sign_ins': int(user.get('total_sign_ins', 0))
                    }
                    for user in api_response.body['users']
                ]
                data['is_api_call'] = True
                
            except ApiException as e:
                data['is_api_call'] = False
                print("Exception when calling UsersApi %s\n" % e)
            except Exception as ex:
                data['is_api_call'] = False
                print(f"Management API not setup: {ex}")

    return render_template(template, **data)

##ADD EMAIL
@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        # Load form data
        form_data = request.form.to_dict()

        # Configuring the email fields
        params = {
            "from": ADMIN_EMAIL,
            "to": [form_data['email']],
            "subject": f"New message from {form_data['name']}!",
            "html": CONTACT_EMAIL.format(**form_data),
        }

        # Sending the email and catching response
        response = resend.Emails.send(params)

        # Handle the response
        if response.get("id"):
            return redirect("/contact")
        else:
            return {"message": "Something went wrong. Please try again."}
    else:
        # Render the contact form
        return render_template("user-contact.html")
@app.route("/search", methods=["POST"])
def search_todo():
    search_term = request.form.get("search")

    if not len(search_term):
        return render_template("todo.html", todos=[])

    res_todos = []
    for todo in todos:
        if search_term in todo["title"]:
            res_todos.append(todo)

    return render_template("todo.html", todos=res_todos)