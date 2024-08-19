FROM python:3.9

ENV JWT_SECRET_KEY="QYmXTKt6bnzaFi76H7R88FQ"

ENV AUTH_SECRET_KEY="django-insecure-zv-czil2aib8@ex@n+k#nh62r-p3r4t3dufvc4at=w"

RUN apt update && apt install -y gcc libmariadb-dev-compat

RUN pip install gunicorn

WORKDIR /app

COPY requirements.txt /app/requirements.txt

RUN pip install -r requirements.txt

COPY . /app

CMD sleep 5

CMD python manage.py migrate

EXPOSE 80/tcp

ENTRYPOINT gunicorn -w 4 -b 0.0.0.0:80 admin.wsgi
