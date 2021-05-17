import csv
import logging
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
        logging.info(f"Adding new row to db: {row}")
        with open(self.path_to_db, 'a') as csvfile:
            db_writer = csv.writer(csvfile)
            db_writer.writerow(row)
        
    def get_entry_by_id(self, target_id):
        with open(self.path_to_db, 'r') as csvfile:
            db_reader = csv.reader(csvfile)
            for id, name in db_reader:
                if id == target_id:
                    return name


