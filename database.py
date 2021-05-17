import csv
import os

class Database:
    def __init__(self, path_to_db='DataBase.csv'):
        self.path_to_db = path_to_db

        if os.path.exists(self.path_to_db):
            # db already exists
            return

        # creates the actual database file
        csvfile = open(self.path_to_db, 'w+')
        db_writer = csv.writer(csvfile)
        db_writer.writerow(["Id", "Name"])
        csvfile.close()

    def add_row_to_db(self, row):
        with open(self.path_to_db, 'a') as csvfile:
            db_writer = csv.writer(csvfile)
            db_writer.writerow(row)




