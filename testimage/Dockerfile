FROM ubuntu
RUN apt-get install -y bash
RUN apt-get install -y python
RUN apt-get install -y telnet
RUN apt-get install -y tcpdump
RUN apt-get install -y apache2
RUN apt-get install -y wget
RUN ls /etc/apache2
RUN mkdir -p /var/lock/apache2
ADD server.py /
ADD down.txt /var/www/html
CMD echo 'source /etc/apache2/envvars | /etc/init.d/apache2 start' | bash && bash
