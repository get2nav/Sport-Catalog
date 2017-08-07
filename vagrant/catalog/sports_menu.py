from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Base, Sports, Essentials

engine = create_engine('sqlite:///sports_db.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()

games = ["Soccer", "Basketball", "Baseball", "Frisbee", "Snowboarding", "Rock Climbing", "Foosball", "Skating", "Hockey"]
# Menu for UrbanBurger
for game in games:
    sport1 = Sports(name=game)
    session.add(sport1 )
    session.commit()

def sports_names():
    menu = session.query(Sports).all()
    for value in menu:
        print value.name


sports_names()
