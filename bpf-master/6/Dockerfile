FROM centos:8
RUN curl https://repos.baslab.org/bpftools.repo --output /etc/yum.repos.d/bpftools.repo
RUN dnf update -y
RUN dnf install -y python2 python36 \
 && alternatives --set python /usr/bin/python2
RUN dnf install -y --nobest bpftrace bpftrace-tools bpftrace-doc bcc bcc-tools bpftool
ENV PATH /usr/share/bcc/tools:/usr/share/bpftrace/tools:$PATH
