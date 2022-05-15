import sqlite3


def connectBD():
    con = sqlite3.connect('./bbdd/auditoria.db')
    return con

def insertTable(con,table,tableName):
    table.to_sql(tableName, con, index=False)  # se crea la tabla en la bd y se anade la var tabla, y se quita el indice

def queryOne(con, queryString):
    cur = con.cursor()
    cur.execute(queryString)
    return cur.fetchone()

def queryAll(con, queryString):
    cur = con.cursor()
    cur.execute(queryString)
    return cur.fetchall()

def sql_remove_all_tables(con):
    cursorObj = con.cursor()
    cursorObj.execute('drop table if exists legal')
    cursorObj.execute('drop table if exists users_info')
    cursorObj.execute('drop table if exists users_ips_dates')
    con.commit()

def close_connection(con):
    con.close()
