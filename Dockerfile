FROM alpine:latest
MAINTAINER Antonios A. Chariton <daknob@daknob.net>

# Install Python 3, pip, and lxml dependencies
RUN apk add --update    python3 \
                        python3-dev \
                        build-base \
                        libxml2 \
                        libxslt \
                        libxml2-dev \
                        libxslt-dev \
                        py-libxml2 \
                        py-libxslt 
RUN python3 -m ensurepip
RUN pip3 install --upgrade pip setuptools

# Move everything inside the image
RUN mkdir /httpswatch
COPY . /httpswatch/.
WORKDIR /httpswatch

# Install the required python modules
RUN pip3 install -r requirements.txt

# Expose port 80
EXPOSE 80

# Expose configuration volume
VOLUME ["/httpswatch/config/"]

# Install nginx
RUN apk add nginx

# Configure nginx
COPY ./docker/nginx.conf /etc/nginx/nginx.conf

# Move Docker Scripts
COPY ./docker/run.sh /bin/run.sh
COPY ./docker/periodic-checks.sh /bin/periodic-checks.sh

# Run nginx + periodic checker
CMD ["/bin/run.sh"]
