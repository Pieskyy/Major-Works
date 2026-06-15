#when adding salting and hasing, the exisiting users were crashing site so i needed to remove them

import sqlite3

con = sqlite3.connect("database_files/database.db")
cur = con.cursor()

cur.execute("DELETE FROM users")

con.commit()
con.close()

