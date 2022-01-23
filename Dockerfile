FROM python:3.9

COPY requirements.txt /
RUN pip3 install -r /requirements.txt

ENV PYTHONUNBUFFERED yes

COPY static/ /static
COPY templates/ /templates
COPY database.py /
COPY passwd.py /
COPY main.py /


ENTRYPOINT ["gunicorn", "main:app", "-w", "2", "--threads", "2", "-b 0.0.0.0:8000", "-R"]

