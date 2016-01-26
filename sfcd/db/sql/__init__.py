import sqlalchemy.ext.declarative


# declare base model for all ORM models
BaseModel = sqlalchemy.ext.declarative.declarative_base()


# create tables for all models with specified engine
def create_tables(engine):
    BaseModel.metadata.create_all(engine)


#import sqlalchemy
#import sqlalchemy.orm

#Engine = sqlalchemy.create_engine('sqlite:///:memory:', echo=True)

#Session = sqlalchemy.orm.sessionmaker(bind=Engine)
