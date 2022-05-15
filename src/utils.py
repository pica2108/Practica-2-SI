import json

def readJson(jsonpath):
    with open(jsonpath) as jsonFile:
        return json.load(jsonFile)  # leer json y devolverlo