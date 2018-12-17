FROM ubuntu:17.10

LABEL maintainer Alexander Merck <alexander.t.merck@gmail.com>
LABEL maintainer Jesse Bowling <jessebowling@gmail.com>
LABEL name "hpfeeds-cif"
LABEL version "0.2"
LABEL release "1"
LABEL summary "HPFeeds CIFv3 handler"
LABEL description "HPFeeds CIFv3 handler is a tool for generating CIFv3 entries for honeypot events."
LABEL authoritative-source-url "https://github.com/CommunityHoneyNetwork/hpfeeds-cif"
LABEL changelog-url "https://github.com/CommunityHoneyNetwork/hpfeeds-cif/commits/master"

ENV playbook "hpfeeds-cif.yml"

RUN apt-get update \
       && apt-get install -y ansible

RUN echo "localhost ansible_connection=local" >> /etc/ansible/hosts
ADD . /opt/
RUN ansible-playbook /opt/${playbook}

ENTRYPOINT ["/usr/bin/runsvdir", "-P", "/etc/service"]