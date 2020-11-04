import os
import sys
import uuid
import random
import logging
import configparser
from hpfeeds.add_user import create_user
from cifsdk.exceptions import AuthError
from cifsdk.client.http import HTTP as Client


def main():
    logging.info("Running build_config.py")
    MONGODB_HOST = os.environ.get("MONGODB_HOST", "mongodb")
    MONGODB_PORT = os.environ.get("MONGODB_PORT", "27017")
    HPFEEDS_HOST = os.environ.get("HPFEEDS_HOST", "hpfeeds3")
    HPFEEDS_PORT = os.environ.get("HPFEEDS_PORT", "10000")
    IDENT = os.environ.get("IDENT", "")
    SECRET = os.environ.get("SECRET", "")
    CHANNELS = os.environ.get("CHANNELS", "amun.events,conpot.events,thug.events,beeswarm.hive,dionaea.capture,dionaea.connections,thug.files,beeswarm.feeder,cuckoo.analysis,kippo.sessions,cowrie.sessions,glastopf.events,glastopf.files,mwbinary.dionaea.sensorunique,snort.alerts,wordpot.events,p0f.events,suricata.events,shockpot.events,elastichoney.events,rdphoney.sessions,uhp.events,elasticpot.events,spylex.events,big-hp.events,ssh-auth-logger.events")
    CIF_HOST = os.environ.get("CIF_HOST", "")
    CIF_TOKEN = os.environ.get("CIF_TOKEN", "")
    CIF_PROVIDER = os.environ.get("CIF_PROVIDER", "")
    CIF_TLP = os.environ.get("CIF_TLP", "")
    CIF_CONFIDENCE = os.environ.get("CIF_CONFIDENCE", "")
    CIF_TAGS = os.environ.get("CIF_TAGS", "")
    CIF_GROUP = os.environ.get("CIF_GROUP", "")
    CIF_VERIFY_SSL = os.environ.get("CIF_VERIFY_SSL", "")
    INCLUDE_HP_TAGS = os.environ.get("INCLUDE_HP_TAGS", "false")
    IGNORE_CIDR = os.environ.get("IGNORE_CIDR", "false")
    CIF_CACHE_DB = os.environ.get("CIF_CACHE_DB", "2")
    CIF_CACHE_EXPIRE = os.environ.get("CIF_CACHE_EXPIRE", "300")

    if IDENT:
        ident = IDENT
    else:
        ident = "hpfeeds-cif-" + str(random.randint(0, 32767))

    if SECRET:
        secret = SECRET
    else:
        secret = str(uuid.uuid4()).replace("-", "")

    config = configparser.ConfigParser()
    config.read("/opt/hpfeeds-cif.cfg.template")
    config['hpfeeds']['ident'] = ident
    config['hpfeeds']['secret'] = secret
    config['hpfeeds']['hp_host'] = HPFEEDS_HOST
    config['hpfeeds']['hp_port'] = HPFEEDS_PORT
    config['hpfeeds']['channels'] = CHANNELS
    config['hpfeeds']['include_hp_tags'] = INCLUDE_HP_TAGS
    config['hpfeeds']['ignore_cidr'] = IGNORE_CIDR

    config['cifv3']['cif_host'] = CIF_HOST
    config['cifv3']['cif_token'] = CIF_TOKEN
    config['cifv3']['cif_provider'] = CIF_PROVIDER
    config['cifv3']['cif_tlp'] = CIF_TLP
    config['cifv3']['cif_confidence'] = CIF_CONFIDENCE
    config['cifv3']['cif_tags'] = CIF_TAGS
    config['cifv3']['cif_group'] = CIF_GROUP
    config['cifv3']['cif_verify_ssl'] = CIF_VERIFY_SSL
    config['cifv3']['cif_cache_db'] = CIF_CACHE_DB
    config['cifv3']['cif_cache_expire'] = CIF_CACHE_EXPIRE

    create_user(host=MONGODB_HOST, port=int(MONGODB_PORT), owner="chn",
                ident=ident, secret=secret, publish="", subscribe=CHANNELS)

    cli = Client(token=CIF_TOKEN, remote=CIF_HOST, verify_ssl=False)
    try:
        ret = cli.ping(write=True)
    except AuthError:
        logging.error("Authentication to %s failed." % CIF_HOST)
        sys.exit(1)

    print("Writing config...")

    with open("/opt/hpfeeds-cif.cfg", 'w') as config_file:
        config.write(config_file)
    sys.exit(0)


if __name__ == "__main__":
    main()
