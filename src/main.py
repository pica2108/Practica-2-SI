import pandas as pd
from dateutil.parser import parser
from werkzeug.exceptions import BadRequestKeyError

from src.SQLite import connectBD, insertTable, queryAll, sql_remove_all_tables, close_connection, queryOne
from src.legal import parseLegalJson
from src.users import parseUsersInfo, parseUsersDatesIps
from flask import Flask, render_template, request, session
from flask_socketio import SocketIO, emit
from threading import Lock
import requests
from sklearn.linear_model import LinearRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
import numpy as np
from datetime import datetime
import json

con = connectBD()
sql_remove_all_tables(con)

legal_table = parseLegalJson()
insertTable(con, legal_table, "legal")

users_table_info = parseUsersInfo()
users_table_ips_dates = parseUsersDatesIps()

insertTable(con, users_table_info, "users_info")
insertTable(con, users_table_ips_dates, "users_ips_dates")
close_connection(con)


def getUsuariosCriticos(topX, min, max):
    con = connectBD()
    users_criticos = queryAll(con,
                              "SELECT username, emailsPhishing, emailsCliclados FROM users_info WHERE emailsPhishing > 0")
    df_users_criticos = pd.DataFrame(users_criticos, columns=['username', 'emailsPhishing', 'emailsCliclados'])
    df_users_criticos['criticidad'] = round(
        df_users_criticos['emailsCliclados'] / df_users_criticos['emailsPhishing'] * 100, 2)
    if min:
        df_users_criticos = df_users_criticos[df_users_criticos.criticidad.gt(min)]
    if max:
        df_users_criticos = df_users_criticos[df_users_criticos.criticidad.lt(max)]
    df_users_criticos = df_users_criticos.sort_values(by=['criticidad'], ascending=False, ignore_index=True).loc[
                        :topX - 1]
    close_connection(con)

    return df_users_criticos


def getWebsVulnerables(topX):
    con = connectBD()
    webs_politicas = queryAll(con, "SELECT web, cookies, aviso, proteccion_de_datos FROM legal")
    df_webs_politicas = pd.DataFrame(webs_politicas, columns=['Web', 'Cookies', 'Aviso', 'Proteccion de datos'])
    df_webs_politicas = df_webs_politicas.sort_values(by=['Cookies', 'Aviso', 'Proteccion de datos'],
                                                      ignore_index=True).loc[:topX - 1]
    close_connection(con)
    return df_webs_politicas


def getUsuario(username):
    if not username:
        return []
    con = connectBD()
    user = queryOne(con, "SELECT * FROM users_info WHERE username='" + username + "'")
    df_user = pd.DataFrame(user)
    close_connection(con)
    print(df_user)
    return list(df_user.values)


def getConexiones():
    con = connectBD()
    dates = queryAll(con, "SELECT dates FROM users_ips_dates")
    df_dates = pd.DataFrame(dates, columns=['dates'])
    date_parser = parser()
    for i in range(len(df_dates)):
        df_dates.loc[i, 'month'] = int(date_parser.parse(df_dates.loc[i, 'dates']).month)
        df_dates.loc[i, 'year'] = int(date_parser.parse(df_dates.loc[i, 'dates']).year)
    close_connection(con)
    return list(df_dates.values)

def regresionLineal():
    print('LINEAR REGRESSION')

    with open('data/users_IA_clases.json') as f:
        data = json.load(f)
    X = []
    y = []
    for usuario in np.asarray(data['usuarios']):
        X.append([usuario['emails_phishing_recibidos'], usuario['emails_phishing_clicados']])
        y.append(usuario['vulnerable'])
    reg = LinearRegression().fit(X, y)
    print(reg.score(X, y))
    with open('data/users_IA_predecir.json') as f:
        data_predecir = json.load(f)
    predecir_X = []
    for usuario in np.asarray(data_predecir['usuarios']):
        predecir_X.append([usuario['emails_phishing_recibidos'], usuario['emails_phishing_clicados']])
    predecir_y = reg.predict((np.array(predecir_X)))
    print(predecir_y)
    return predecir_y

def decisionTree():
    print('DECISION TREE')
    with open('data/users_IA_clases.json') as f:
        data = json.load(f)
    X = []
    y = []
    for usuario in np.asarray(data['usuarios']):
        X.append([usuario['emails_phishing_recibidos'], usuario['emails_phishing_clicados']])
        y.append(usuario['vulnerable'])
    reg = DecisionTreeClassifier().fit(X, y)
    print(reg.score(X, y))
    with open('data/users_IA_predecir.json') as f:
        data_predecir = json.load(f)
    predecir_X = []
    for usuario in np.asarray(data_predecir['usuarios']):
        predecir_X.append([usuario['emails_phishing_recibidos'], usuario['emails_phishing_clicados']])
    predecir_y = reg.predict((np.array(predecir_X)))
    print(predecir_y)
    return predecir_y

def randomForest():
    print('RANDOM FOREST')
    with open('data/users_IA_clases.json') as f:
        data = json.load(f)
    X = []
    y = []
    for usuario in np.asarray(data['usuarios']):
        X.append([usuario['emails_phishing_recibidos'], usuario['emails_phishing_clicados']])
        y.append(usuario['vulnerable'])
    reg = RandomForestClassifier().fit(X, y)
    print(reg.score(X, y))
    with open('data/users_IA_predecir.json') as f:
        data_predecir = json.load(f)
    predecir_X = []
    for usuario in np.asarray(data_predecir['usuarios']):
        predecir_X.append([usuario['emails_phishing_recibidos'], usuario['emails_phishing_clicados']])
    predecir_y = reg.predict((np.array(predecir_X)))
    print(predecir_y)
    return predecir_y


async_mode = None
app = Flask(__name__)
socketio = SocketIO(app, async_mode=async_mode)
thread = None
thread_lock = Lock()

cve_url = 'https://cve.circl.lu/api/last'


def background_cve_thread():
    # Actualización de vulnerabilidades cada 10 segundos
    vulnerabilidades = ((requests.get(cve_url)).json())[:10]
    socketio.emit('vulnerabilidades-socket-event', vulnerabilidades)
    while True:
        socketio.sleep(10)
        vulnerabilidades = ((requests.get(cve_url)).json())[:10]
        socketio.emit('vulnerabilidades-socket-event', vulnerabilidades)


@app.route('/', methods=['GET', 'POST'])
def ejercicio1():
    # Default state
    num_usuarios = 10
    min_criticidad_usuarios = None
    max_criticidad_usuarios = None
    num_webs = 10
    username = ''

    # Default info
    usuarios = list(getUsuariosCriticos(num_usuarios, min_criticidad_usuarios, max_criticidad_usuarios).values)
    webs = list(getWebsVulnerables(num_webs).values)
    username_info = getUsuario(username)
    conexiones = getConexiones()

    # Users table
    if request.method == 'POST' and int(request.form['top_user']) != num_usuarios or (
            request.form.get('min_criticidad') or request.form.get('max_criticidad')):
        if request.form.get('min_criticidad'):
            min_criticidad_usuarios = int(request.form.get('min_criticidad'))
        if request.form.get('max_criticidad'):
            max_criticidad_usuarios = int(request.form.get('max_criticidad'))
        num_usuarios = int(request.form['top_user'])
        usuarios = list(getUsuariosCriticos(num_usuarios, min_criticidad_usuarios, max_criticidad_usuarios).values)

    # Webs table
    if request.method == 'POST' and int(request.form['top_webs']) != num_webs:
        num_webs = int(request.form['top_webs'])
        webs = list(getWebsVulnerables(num_webs).values)

    # User info
    print(username)
    if request.method == 'POST' and request.form['username']:
        username = request.form['username']
        username_info = getUsuario(username)

    regresionLineal()
    decisionTree()
    randomForest()

    return render_template('ejercicio2.html',
                           webs=webs,
                           usuarios=usuarios,
                           min_criticidad_usuarios=min_criticidad_usuarios,
                           max_criticidad_usuarios=max_criticidad_usuarios,
                           username_info=username_info,
                           conexiones=conexiones,
                           async_mode=socketio.async_mode)


@socketio.event
def connect():
    global thread
    with thread_lock:
        if thread is None:
            thread = socketio.start_background_task(background_cve_thread)


if __name__ == '__main__':
    socketio.run(app, debug=True)
