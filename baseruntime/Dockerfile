ARG baseImage=centos:centos7.9.2009
FROM ${baseImage}

COPY entrypoint.sh /
RUN yum install -y telnet iproute net-tools
WORKDIR /

CMD ["/entrypoint.sh"]



