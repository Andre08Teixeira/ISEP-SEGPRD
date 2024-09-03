from flask import Flask, request

app = Flask(__name__)

@app.route('/admin')
def admin():
    return 'Olá Administrador'

@app.route('/client')
def client():
    issuerInfo = request.environ.get('SSL_CLIENT_I_DN')
    subjectInfo = request.environ.get('SSL_CLIENT_S_DN')
    
    return f'''
        <h1>Olá {subjectInfo.split(' ')[0]} :D</h1>
        <h3>Certificado emitido por:</h3>
        <ul>
            <li>C = {issuerInfo['C']}</li>
            <li>ST = {issuerInfo['ST']}</li>
            <li>L = {issuerInfo['L']}</li>
            <li>O = {issuerInfo['O']}</li>
            <li>OU = {issuerInfo['OU']}</li>
            <li>CN = {issuerInfo['CN']}</li>
            <li>emailAddress = {issuerInfo['emailAddress']}</li>
        </ul>
    '''

if __name__ == '__main__':
    app.run(debug=True, ssl_context=('cert/server.crt', 'cert/server.key'), port=5000)
