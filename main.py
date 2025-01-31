from flask import Flask, request, Response, abort, redirect, render_template
from flask_cors import CORS
from pymongo import MongoClient
from dotenv import load_dotenv
import json
import hashlib
import datetime
import secrets
import os

# Загрузка переменных окружения из файла .env
load_dotenv()

app = Flask('', template_folder="", static_folder="static")
cors = CORS(app, resources={r"/api/*": {"origins": "*"}, r"/clapi/*": {"origins": "*"}})
accounts_creating_is_blocked = False
admins = ['iri']

# Подключение к MongoDB
MONGO_URI = os.getenv('MONGO_URI', 'mongodb://localhost:27017/')
client = MongoClient(MONGO_URI)
db = client[os.getenv('MONGO_DB_NAME', 'riauth')]
users_collection = db['users']
tokens_collection = db['tokens']

def is_allowed(string):
    allowed_chars = 'qwertyuiopasdfghjkl;QWERTYUIOPASDFGHJKLZXCVBNM{}:<>[]zxcvbnm,.1234567890-=+_!@$%&^*()`~ '
    return all(char in allowed_chars for char in string)

def valid_auth(username, password=None):
    if password:
        user = users_collection.find_one({"username": username})
        if user and password == user['password']:
            return True
        return False
    else:
        token = tokens_collection.find_one({"token": username})
        if token and token['expires'] > datetime.datetime.now().timestamp():
            return token['user']
        return False

def generate_response(status_code, status_name, msg, additional_data=None):
    response_data = {
        "status_code": status_code,
        "status_name": status_name,
        "msg": msg
    }
    if additional_data:
        response_data.update(additional_data)
    return Response(response=json.dumps(response_data), status=status_code, mimetype="application/json")

@app.route('/clapi/irinet/is_auth_valid', methods=['POST'])
def is_auth_valid():
    data = json.loads(request.get_data())
    password_hash = hashlib.sha512(data['password'].encode('utf-8')).hexdigest()
    auth_result = valid_auth(data['username'], password_hash)
    if auth_result == 'not':
        return generate_response(403, "OK", "Noname", {"hash": password_hash})
    elif auth_result:
        return generate_response(200, "OK", "Данные для входа верны:)", {"hash": password_hash})
    else:
        return generate_response(403, "FALSE", "Логин или пароль неверны")

@app.route('/clapi/irinet/is_auth_valid_hash', methods=['POST'])
def is_auth_valid_hash():
    data = json.loads(request.get_data())
    if valid_auth(data['username'], data['password']):
        return generate_response(200, "OK", "Данные для входа верны:)")
    else:
        return generate_response(403, "FALSE", "Логин или пароль неверны")

@app.route('/api/irinet/is_auth_valid_token', methods=['GET'])
def is_auth_valid_token():
    token = request.args.get('token')
    if token:
        auth_result = valid_auth(token)
        if auth_result:
            user = users_collection.find_one({"username": auth_result})
            return generate_response(200, "OK", "Токен существует и не истёк", {
                "username": auth_result,
                "name": user["name"]
            })
        else:
            return generate_response(403, "EXPIRED", "Токен неверен или истёк")
    else:
        abort(417, 'Отсутствует токен в параметре запроса token')

@app.route('/api/auth')
def auth_on_other_sites():
    color = request.args.get('color', '000000')
    logo = request.args.get('logo', '../static/riauth.svg')
    bg = request.args.get('bg', 'https://cdn.discordapp.com/attachments/706221390289961101/1057304820572233818/logo.png')
    if valid_auth(request.cookies.get('username'), request.cookies.get('pwd')) not in ['not', False]:
        log = "true"
    else:
        log = "false"
    return render_template('iriauthnew.html', log=log, color=color, logo=logo, bg=bg)

@app.route('/api/generate_token/<login>/<pwd>/<hours>')
def generate_token(login, pwd, hours):
    if valid_auth(login, pwd) not in ['not', False]:
        uri = request.args.get('uri')
        by = request.args.get('by')
        if uri and by:
            token = secrets.token_hex(64)
            tokens_collection.insert_one({
                "token": token,
                "user": login,
                "expires": datetime.datetime.now().timestamp() + (int(hours) * 60 * 60),
                "by": by
            })
            return redirect(f'{uri}?iritoken={token}', 307)
        else:
            abort(417, 'Не указан URL для перенаправления в параметре запроса uri или автор запроса в параметре запроса by')
    else:
        return abort(401)

@app.route('/ovk/token', methods=['POST', 'GET'])
def generate_token_ovk():
    login = request.args.get('username')
    pwd = hashlib.sha512(request.args.get('password').encode('utf-8')).hexdigest()
    hours = 730
    if valid_auth(login, pwd) not in ['not', False]:
        token = secrets.token_hex(64)
        tokens_collection.insert_one({
            "token": token,
            "user": login,
            "expires": datetime.datetime.now().timestamp() + (int(hours) * 60 * 60),
            "by": request.args.get('by')
        })
        user = users_collection.find_one({"username": login})
        return generate_response(200, "OK", "None", {
            "access_token": token,
            "expires_in": 0,
            "user_id": user['_id']
        })
    else:
        return generate_response(400, "FALSE", "Invalid username or password")

@app.route('/api/irinet/user', methods=['POST', 'GET', 'PUT'])
def irinet_api_register():
    global accounts_creating_is_blocked
    if request.method == 'PUT':
        return update_user()
    elif request.method == 'GET':
        return get_user()
    elif request.method == 'POST':
        return create_user()

def update_user():
    data = json.loads(request.get_data())
    if valid_auth(data['auth']['login'], data['auth']['pwd']):
        update_fields = {}
        if data['check']['name']:
            update_fields['name'] = data['data']['name']
        if data['check']['ava']:
            update_fields['avatar_url'] = data['data']['ava']
        if data['check']['ds']:
            update_fields['desc'] = data['data']['ds']
        if data['check']['bg']:
            update_fields['bg'] = data['data']['bg']
        if data['check']['vk']:
            update_fields['vkid'] = data['data']['vk']
        if data['check'].get('discord') and data['data']['discord'].startswith('https://discord.com/api/webhooks'):
            update_fields['discord'] = data['data']['discord']
        users_collection.update_one({"username": data['auth']['login']}, {"$set": update_fields})
        return generate_response(200, "OK", "None")
    else:
        return generate_response(403, "BAD_AUTH", "Авторизация не прошла успешно.")

def get_user():
    username = request.args.get('username')
    if not username:
        return generate_response(403, "WRONG_ARGS", "Your args doesn't have necessary keys.")
    user = users_collection.find_one({"username": username})
    if user:
        return generate_response(200, "OK", "None", {
            "username": username,
            "name": user['name'],
            "avatar_url": user['avatar_url'],
            "friends": user['friends'],
            "desc": user['desc'],
            "bg": user['bg'],
            "posts": user['posts']
        })
    else:
        bot = users_collection.find_one({"username": username, "is_bot": True})
        if bot:
            return generate_response(200, "OK", "None", {
                "username": username,
                "name": bot['name'],
                "avatar_url": bot['avatar_url']
            })
        else:
            return generate_response(404, "WRONG_USER", "Такого пользователя не существует.")

def create_user():
    global accounts_creating_is_blocked
    if accounts_creating_is_blocked:
        return generate_response(405, "METHOD_IS_NOT_ALLOWED", "Регистрация временно недоступна.")
    data = json.loads(request.get_data())
    if data['username'].endswith('bot'):
        return generate_response(403, "SHOULD_NOT_END_WITH_BOT", "Юзернейм человека не должен кончаться с bot.")
    if not all(key in data for key in ['username', 'name', 'password']):
        return generate_response(403, "WRONG_BODY", "Your body doesn't have necessary keys.")
    if not (is_allowed(data['username']) and is_allowed(data['password'])):
        return generate_response(403, "DISALLOWED_CHARACTERS", "Вы использовали запрещенные символы.")
    if users_collection.find_one({"username": data['username']}):
        return generate_response(403, "ALREADY_EXIST", "Аккаунт с этим юзернеймом уже существует.")
    if len(data['name']) > 20:
        return generate_response(403, "TOO_LONG_NAME", "Имя не может быть длиннее 20 символов.")
    if len(data['name']) < 2:
        return generate_response(403, "TOO_SHORT_NAME", "Имя не может быть меньше 2 символов.")
    if len(data['username']) > 20:
        return generate_response(403, "TOO_LONG_USERNAME", "Юзернейм не может быть длиннее 20 символов")
    if len(data['username']) == 0:
        return generate_response(403, "TOO_SHORT_USERNAME", "Логин и пароль тоже надо написать на предыдущем экране:(")
    if len(data['username']) < 6:
        return generate_response(403, "TOO_SHORT_USERNAME", "Юзернейм не может быть меньше 6 символов.")
    if len(data['password']) > 50:
        return generate_response(403, "TOO_LONG_PASSWORD", "Пароль не может быть длиннее 50 символов")
    if len(data['password']) < 6:
        return generate_response(403, "TOO_SHORT_PASSWORD", "Пароль не может быть меньше 6 символов.")
    if len(data['sw']) < 1:
        return generate_response(403, "WHERE_IS_SECRET_WORD", "Введите секретное слово. Оно нужно для восстановления пароля!")
    password_hash = hashlib.sha512(data['password'].encode('utf-8')).hexdigest()
    users_collection.insert_one({
        'username': data['username'],
        'name': data['name'],
        'password': password_hash,
        'avatar_url': 'https://isamiri.pythonanywhere.com/contents/irinet/default_ava.png',
        'desc': '',
        'friends': [],
        'notes': [],
        'bg': '#232323',
        'vkid': None,
        'posts': [],
        'secret_word': data['sw']
    })
    return generate_response(200, "OK", "Account created.")

if __name__ == '__main__':
    app.run()