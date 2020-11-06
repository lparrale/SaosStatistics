import sqlite3

conn=sqlite3.connect('Statistics.sqlite')

cursor=conn.cursor()
sql_query="""CREATE TABLE NEs (
    NEId TEXT UNIQUE
              NOT NULL
              PRIMARY KEY,
    name TEXT NOT NULL,
    ip   TEXT NOT NULL
);


"""
cursor.execute(sql_query)
