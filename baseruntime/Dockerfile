ARG baseImage=centos:centos7.9.2009
FROM ${baseImage}

COPY entrypoint.sh /
RUN rm -f /etc/yum.repos.d/*
RUN cd /etc/yum.repos.d/ && curl -O http://mirrors.aliyun.com/repo/Centos-7.repo

RUN yum install -y telnet iproute net-tools
WORKDIR /

CMD ["/entrypoint.sh"]



