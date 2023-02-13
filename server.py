import os
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'

from fastapi import FastAPI, Request
from starlette.responses import RedirectResponse
from starlette.middleware.sessions import SessionMiddleware

from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware

import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery
import urllib.parse

app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key="SECRET-KEY", max_age=None)

app.mount("/static", StaticFiles(directory="static"), name="static")

templates = Jinja2Templates(directory="templates")

origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


CLIENT_SECRETS_FILE = "client_secret.json"
SCOPES = ['openid', 'https://www.googleapis.com/auth/drive.metadata.readonly']
API_SERVICE_NAME = 'drive'
API_VERSION = 'v3'


@app.get("/login_page")
def show_login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request}) 

@app.get("/list_files")
def show_files_list(request: Request):
    if 'credentials' not in request.session:
        return RedirectResponse(url='http://localhost:8080/authorize')

    credentials = google.oauth2.credentials.Credentials(
        **request.session.get('credentials'))

    drive = googleapiclient.discovery.build(
        API_SERVICE_NAME, API_VERSION, credentials=credentials)

    files = drive.files().list().execute()

    request.session['credentials'] = credentials_to_dict(credentials)
    files_list = files['files']
    file_names = list()
    for file in files_list:
        if file["mimeType"] == "application/pdf":
            file_names.append(file["name"])
    file_dict = {"files":file_names}
    return templates.TemplateResponse("files.html", {"request":request, "data":file_dict})
    return file_dict

@app.get("/authorize")
def authorize_user(request: Request):
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES)

    flow.redirect_uri = "http://localhost:8080/oauth2callback"
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true')

    request.session['state'] = state
    return RedirectResponse(url=authorization_url) 

@app.get("/oauth2callback")
def callback_oauth(request: Request):
    state = request.session.get('state')

    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES, state=state)
    flow.redirect_uri = "http://localhost:8080/oauth2callback" 


    authorization_response = str(request.url)
    parsed_url = urllib.parse.urlsplit(authorization_response)
    query_params = urllib.parse.parse_qs(parsed_url.query)

    code = query_params['code'][0]
    flow.fetch_token(code=code)

    credentials = flow.credentials
    request.session['credentials'] = credentials_to_dict(credentials)
    return RedirectResponse(url="http://localhost:8080/list_files")


def credentials_to_dict(credentials):
  return {'token': credentials.token,
          'refresh_token': credentials.refresh_token,
          'token_uri': credentials.token_uri,
          'client_id': credentials.client_id,
          'client_secret': credentials.client_secret,
          'scopes': credentials.scopes}
