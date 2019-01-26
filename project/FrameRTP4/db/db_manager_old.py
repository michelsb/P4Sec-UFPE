from sqlalchemy import create_engine
from sqlalchemy import Table, Column, Integer, String, Boolean, MetaData, ForeignKey
# Global Variables
SQLITE = 'sqlite'

# Table Names
COUNTERS = 'counter_arrays'
ACTIONS = 'actions'
TABLES = 'tables'

class DBManager:
    # http://docs.sqlalchemy.org/en/latest/core/engines.html
    DB_ENGINE = {
        SQLITE: 'sqlite:///{DB}'
    }

    # Main DB Connection Ref Obj
    db_engine = None
    def __init__(self, dbtype, username='', password='', dbname=''):
        dbtype = dbtype.lower()
        if dbtype in self.DB_ENGINE.keys():
            engine_url = self.DB_ENGINE[dbtype].format(DB=dbname)
            self.db_engine = create_engine(engine_url)
            print(self.db_engine)
        else:
            print("DBType is not found in DB_ENGINE")

    def create_db_tables(self):
        metadata = MetaData()
        counters = Table(COUNTERS, metadata,
                         Column('id', Integer, primary_key=True),
                         Column('name', String, nullable=False),
                         Column('size', Integer, nullable=False),
                         Column('is_direct', Boolean, default=False, nullable=False)
                         )
        actions = Table(ACTIONS, metadata,
                        Column('id', Integer, primary_key=True),
                        Column('name', String, nullable=False),
                        Column('runtime_data', String)
                        )

        try:
            metadata.create_all(self.db_engine)
            print("Tables created")
        except Exception as e:
            print("Error occurred during Table creation!")
            print(e)

    # Insert, Update, Delete
    def execute_query(self, query=''):
        if query == '' : return
        print (query)
        with self.db_engine.connect() as connection:
            try:
                connection.execute(query)
            except Exception as e:
                print(e)

    def print_all_data(self, table='', query=''):
        query = query if query != '' else "SELECT * FROM '{}';".format(table)
        print(query)
        with self.db_engine.connect() as connection:
            try:
                result = connection.execute(query)
            except Exception as e:
                print(e)
            else:
                for row in result:
                    print(row)  # print(row[0], row[1], row[2])
                result.close()
        print("\n")

    # Examples
    def sample_query(self):
        # Sample Query
        query = "SELECT first_name, last_name FROM {TBL_USR} WHERE " \
                "last_name LIKE 'M%';".format(TBL_USR=USERS)
        self.print_all_data(query=query)
        # Sample Query Joining
        query = "SELECT u.last_name as last_name, " \
                "a.email as email, a.address as address " \
                "FROM {TBL_USR} AS u " \
                "LEFT JOIN {TBL_ADDR} as a " \
                "WHERE u.id=a.user_id AND u.last_name LIKE 'M%';" \
            .format(TBL_USR=USERS, TBL_ADDR=ADDRESSES)
        self.print_all_data(query=query)

    def sample_delete(self):
        # Delete Data by Id
        query = "DELETE FROM {} WHERE id=3".format(USERS)
        self.execute_query(query)
        self.print_all_data(USERS)
        # Delete All Data
        '''
        query = "DELETE FROM {}".format(USERS)
        self.execute_query(query)
        self.print_all_data(USERS)
        '''

    def sample_insert(self):
        # Insert Data
        query = "INSERT INTO {}(id, first_name, last_name) " \
                "VALUES (3, 'Terrence','Jordan');".format(USERS)
        self.execute_query(query)
        self.print_all_data(USERS)

    def sample_update(self):
        # Update Data
        query = "UPDATE {} set first_name='XXXX' WHERE id={id}"\
            .format(USERS, id=3)
        self.execute_query(query)
        self.print_all_data(USERS)

