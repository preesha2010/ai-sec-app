from flask import Flask, request

app = Flask(__name__)

@app.route('/')
def home():
    return 'App is running!'

@app.route('/login')
def login():
    username = request.args.get('username')
    return f'Hello, {username}!'

if __name__ == '__main__':
    app.run(debug=True)