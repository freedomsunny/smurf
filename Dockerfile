FROM opsbase:latest
MAINTAINER huangyj
COPY smurf /root/smurf
WORKDIR /root/smurf
RUN yum -y install mysql-connector-python.noarch \
    && mkdir -p /var/log/smurf/ \
    && pip install -r requirements.txt
CMD sh /root/smurf/start.sh