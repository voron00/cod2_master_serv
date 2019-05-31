FROM perl:5-slim-threaded
COPY . /usr/src/master
WORKDIR /usr/src/master
CMD [ "perl", "./master.pl" ]