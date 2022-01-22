import peewee as pw
import datetime as dt

db = pw.SqliteDatabase('links.db')

class MyModel(pw.Model):
    class Meta:
        database = db


class Link(MyModel):
    name = pw.CharField()
    description = pw.TextField()
    slug = pw.CharField(unique=True)
    target_url = pw.CharField()

class Visit(MyModel):
    link = pw.ForeignKeyField(Link, backref='links')
    date_accessed = pw.DateTimeField(default=dt.datetime.now)
    ip_address = pw.IPField()

db.create_tables([Link, Visit])
