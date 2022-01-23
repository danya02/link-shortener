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

class User(MyModel):
    username = pw.CharField(unique=True)
    user_handle = pw.BlobField()

class Credential(MyModel):
    user = pw.ForeignKeyField(User)
    raw_id = pw.BlobField()
    signature_count = pw.IntegerField(null=True)
    public_key = pw.BlobField()

class Challenge(MyModel):
    user = pw.ForeignKeyField(User)
    request = pw.BlobField()
    dt = pw.DateTimeField(default=dt.datetime.now)

db.create_tables([Link, Visit, User, Credential, Challenge])
