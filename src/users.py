import numpy as np
import pandas as pd

from src.utils import readJson


def isMissing(user):
    for user_key in user.keys():
        if user[user_key] == 'None' or user[user_key] == -1:
            return 1
    return 0

def parseUsersInfo():
    data_users = readJson("./data/users.json")
    data_username_list = []
    for users_username in data_users['usuarios']:
        username = list(users_username.keys())[0]
        user_info = users_username[username]
        user_info['isMissing'] = isMissing(user_info)
        del user_info["ips"]
        del user_info["fechas"]
        user_info['username'] = username
        data_username_list.append(user_info)
    df_users = pd.json_normalize(data_username_list)
    return df_users.rename(columns={'emails.total': 'emailsTotal', 'emails.phishing': 'emailsPhishing', 'emails.cliclados': 'emailsCliclados'})



def parseUsersDatesIps():
    data_users = readJson("./data/users.json")
    df_ips_dates = pd.DataFrame()
    for users_username in data_users['usuarios']:
        username = list(users_username.keys())[0]
        user_info = users_username[username]
        aux = {
            "ips": np.array(user_info["ips"]),
            "dates": np.array(user_info["fechas"]),
            "username": username,
            "isMissing": isMissing(user_info)
        }
        df_aux = pd.DataFrame(aux)
        df_ips_dates = pd.concat([df_ips_dates, df_aux])
    return df_ips_dates