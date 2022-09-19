import os
import mysql.connector

db_host = os.getenv('DB_HOST')
#db_port = os.getenv('DB_PORT')
db_port = 3306
db_pwd = os.getenv('DB_PWD')
db_name = os.getenv('DB_NAME') # device_db
table_name = 'devices'

def open_connection():
    db = mysql.connector.connect(host=db_host, database=db_name, user='root', password=db_pwd, port=db_port)
    return db

def close_connection(db):
    db.close()

def create_database(cursor, dbName):
    cursor.execute("CREATE DATABASE {}".format(dbName))

def insert_data(db, cursor, val):
    sql_query = "INSERT INTO {} (device_id, device_name, device_type, controller_gateway) VALUES (%s, %s, %s, %s)".format(table_name)
   
    cursor.execute(sql_query, val)
    db.commit()

def fetch_all(cursor):
    query = "SELECT * FROM {}".format(table_name)
    cursor.execute(query)
    all_result = cursor.fetchall()
    result_dicts = {}
    for result in all_result:
        result_dict = {'device_id':result[0], 'device_name': result[1], 'device_type': result[2], 'controller_gateway': result[3]}
        result_dicts[result[0]] = result_dict
    return result_dicts

def fetch_with_id(cursor, device_id):
    query = "SELECT * FROM {} where device_id = {}".format(table_name, device_id)
    cursor.execute(query)
    result = cursor.fetchall()
    result_dict = {'device_id' : result[0][0], 'device_name': result[0][1], 'device_type': result[0][2], 'controller_gateway': result[0][3]}
    return result_dict

def delete_data(db, cursor, device_id):
    query = "DELETE FROM {} WHERE device_id = {}".format(table_name, device_id)
    cursor.execute(query)
    db.commit()

def get_all_ids(cursor):
    query = "SELECT * FROM {}".format(table_name)
    cursor.execute(query)
    all_result = cursor.fetchall()
    id_list = []
    for result in all_result:
        id_list.append(result[0])
    return id_list

if __name__ == '__main__':

    db = open_connection()
    cursor = db.cursor()

    #val1 = ("400", "Samsung TV", "TV", "1.1.1.1")
    #insert_data(db, cursor, val1)
    
    #all_result = fetch_all(cursor)
    #print(all_result)
    #for x in all_result:
    #    print(x)

    #result = fetch_with_id(cursor, "300")
    #print(result)

    #delete_data(db, cursor, "400")


    close_connection(db)
