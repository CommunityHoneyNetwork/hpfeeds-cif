FROM ubuntu:18.04

LABEL maintainer Team STINGAR <team-stingar@duke.edu>
LABEL name "hpfeeds-cif"
LABEL version "1.9"
LABEL release "1"
LABEL summary "HPFeeds CIFv3 handler"
LABEL description "HPFeeds CIFv3 handler is a tool for generating CIFv3 submissions for honeypot events."
LABEL authoritative-source-url "https://github.com/CommunityHoneyNetwork/hpfeeds-cif"
LABEL changelog-url "https://github.com/CommunityHoneyNetwork/hpfeeds-cif/commits/master"

ENV DEBIAN_FRONTEND "noninteractive"

# hadolint ignore=DL3008,DL3005
RUN apt-get update \
  && apt-get upgrade -y \
  && apt-get install --no-install-recommends -y gcc git python3-dev python3-pip \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /opt/requirements.txt
RUN python3 -m pip install --upgrade pip setuptools wheel \
  && python3 -m pip install -r /opt/requirements.txt \
  && python3 -m pip install git+https://github.com/CommunityHoneyNetwork/hpfeeds3.git

COPY . /opt/
RUN chmod 0755 /opt/entrypoint.sh

ENTRYPOINT ["/opt/entrypoint.sh"]
