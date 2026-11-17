import pymysql

def get_db():
    return pymysql.connect(
        host="localhost",
        user="root",
        password="",            # XAMPP default is empty
        database="hotel_security",
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=True,
    )