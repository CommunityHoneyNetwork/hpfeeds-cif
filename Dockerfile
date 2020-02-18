FROM ubuntu:18.04

LABEL maintainer Team STINGAR <team-stingar@duke.edu>
LABEL name "hpfeeds-cif"
LABEL version "1.9"
LABEL release "1"
LABEL summary "HPFeeds CIFv3 handler"
LABEL description "HPFeeds CIFv3 handler is a tool for generating CIFv3 entries for honeypot events."
LABEL authoritative-source-url "https://github.com/CommunityHoneyNetwork/hpfeeds-cif"
LABEL changelog-url "https://github.com/CommunityHoneyNetwork/hpfeeds-cif/commits/master"

COPY requirements.txt /opt/requirements.txt

RUN apt-get update && apt-get install -y gcc git python3-dev python3-pip
RUN pip3 install -r /opt/requirements.txt
RUN pip3 install git+https://github.com/CommunityHoneyNetwork/hpfeeds3.git

ADD . /opt/
RUN chmod 755 /opt/entrypoint.sh

ENTRYPOINT ["/opt/entrypoint.sh"]
