import pandas as pd

from src.utils import readJson

def parseLegalJson():
    data_legal = readJson("./data/legal.json")
    data_webs_list = []
    for legal_webs in data_legal[
        'legal']:  # dentro del array legal cada uno de los objetos del json estara en la var legal_webs
        web = list(legal_webs.keys())[0]  # sacamos la clave de cada objeto que es el nombre de la web
        web_info = legal_webs[web]  # con la clave sacada en la var web, se obtiene su info
        web_info['web'] = web  # se anade a la info el nombre de la web, para que este all al mismo nivel
        data_webs_list.append(web_info)  # se mete all en el array data_web_list
    return pd.json_normalize(data_webs_list)  # se crea una var tabla con all lo del array