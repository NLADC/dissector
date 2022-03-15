import requests
import urllib3
from pymisp import ExpandedPyMISP, MISPEvent, MISPObject
import json
import time

from logger import LOGGER


# ------------------------------------------------------------------------------
def search_misp_events(host, token, protocol, noverify, filter={}):
    misp_events = None

    LOGGER.debug("Searching MISP events with filter: {}".format(filter))

    if noverify:
        urllib3.disable_warnings()
    r = requests.post("{0}://{1}{2}{3}".format(protocol, host, "/events/index", ""),
                      json=filter,
                      headers={'Authorization': token,
                               'Accept': 'application/json'},
                      timeout=10, verify=not noverify)
    LOGGER.debug("status:{}".format(r.status_code))
    if r.status_code == 200:
        misp_events = r.json()

    return misp_events


# ------------------------------------------------------------------------------
def add_misp_tag(host, token, protocol, noverify, tag_name, tag_colour):
    misp_tag = None

    LOGGER.debug(f"Creating a {tag_name} tag")

    try:
        if noverify:
            urllib3.disable_warnings()
        r = requests.post("{0}://{1}{2}{3}".format(protocol, host, "/tags/add/", ""),
                          json={'name': tag_name, 'colour': tag_colour},
                          headers={'Authorization': token,
                                   'Accept': 'application/json'},
                          timeout=10, verify=not noverify)
        LOGGER.debug("status:{}".format(r.status_code))
        if r.status_code == 200:
            misp_tag = r.json()
    except Exception as e:
        LOGGER.error("{}".format(e))

    return misp_tag


# ------------------------------------------------------------------------------
def add_misp_tag_to_event(host, token, protocol, noverify, event_id, tag_id):
    misp_tag = None
    LOGGER.debug("Adding DDoSCH tag to the event")

    try:
        if noverify:
            urllib3.disable_warnings()
        r = requests.post("{0}://{1}{2}{3}/{4}".format(protocol, host, "/events/addTag/", event_id, tag_id),
                          headers={'Authorization': token,
                                   'Accept': 'application/json'},
                          timeout=10, verify=not noverify)
        LOGGER.debug("status:{}".format(r.status_code))
        if r.status_code == 200:
            misp_tag = r.json()
    except Exception as e:
        LOGGER.error("{}".format(e))

    return misp_tag


# ------------------------------------------------------------------------------
def add_misp_fingerprint(host, token, protocol, noverify, fp):
    LOGGER.info("Uploading the fingerprint to MISP")
    start = time.time()

    # Maximum number of source IPs to include
    # 0 means all (no limit)
    source_ips_limit = 1

    # Possible dicts in each attack_vector of the fingerprint
    # that will be added as comments (with the dict as value) to the event (not the ddos objects)
    attack_vector_dicts = [
        'ttl',
        'tcp_flags',
        'fragmentation_offset',
        'ethernet_type',
        'frame_len',
        'dns_query_name',
        'dns_query_type',
        'ICMP type',
        'ntp_requestcode',
        'http_uri',
        'http_method',
        'http_user_agent',
    ]

    # Possible fields in each attack_vector of the fingerprint
    # that will be added as comments to the event (not the ddos objects)
    attack_vector_fields = [
        'service',
        'fraction_of_attack',
        'nr_flows',
        'nr_packets',
        'nr_megabytes',
        'time_start',
        'duration_seconds',
    ]

    # Possible fields in the fingerprint
    # that will be added as comments to the event
    fingerprint_fields = [
        'time_start',
        'duration_seconds',
        'total_flows',
        'total_megabytes',
        'total_packets',
        'total_ips',
        'avg_bps',
        'avg_pps',
        'avg_Bpp',
    ]

    try:
        misp = ExpandedPyMISP(f'{protocol}://{host}', token, ssl=not noverify, tool="dissector", debug=False)

        # Create the DDoSCH tag (returns existing one if already present)
        ddosch_tag = add_misp_tag(host, token, protocol, noverify, 'DDoSCH', '#ff7dfd')
        LOGGER.debug(ddosch_tag)

        # Create an event to link everything to
        LOGGER.debug("Creating a new event for the fingerprint")
        event = MISPEvent()
        event.info = fp['key']

        # TARGET
        event.add_attribute(category='Network activity', type='ip-dst', value=fp['target'], comment='target')
        # KEY
        event.add_attribute(category='Network activity', type='md5', value=fp['key'], comment='attack key')

        LOGGER.debug('Adding fingerprint fields')
        for fp_field in fingerprint_fields:
            if fp_field in fp:
                event.add_attribute(category='Network activity',
                                    type='comment',
                                    value=fp[fp_field],
                                    comment=fp_field)

        # TAGS
        if 'tags' in fp:
            LOGGER.debug('Adding fingerprint tags')
            for tag in fp['tags']:
                event.add_tag(tag=tag)
        event.add_tag(tag='validated')

        # ATTACK VECTORS
        for attack_vector, i in zip(fp['attack_vectors'], range(len(fp['attack_vectors']))):
            LOGGER.debug(f'Processing Attack Vector #{i}')
            ddos = MISPObject(name="ddos")
            # ATTACK VECTOR PROTOCOL
            ddos.add_attribute('protocol',
                               attack_vector['protocol'],
                               comment=f'vector {i}')

            for av_dict in attack_vector_dicts:
                if av_dict in attack_vector and type(attack_vector[av_dict]) == dict:
                    LOGGER.debug(f'Adding dict {av_dict}')
                    event.add_attribute(category='Network activity', type='comment',
                                        value=json.dumps(attack_vector[av_dict]),
                                        comment=f'vector {i} {av_dict} ({av_dict}:fraction)')

            for av_field in attack_vector_fields:
                if av_field in attack_vector and attack_vector[av_field]:
                    LOGGER.debug(f'Adding field {av_field}')
                    event.add_attribute(category='Network activity', type='comment',
                                        value=attack_vector[av_field],
                                        comment=f'vector {i} {av_field}')

            # ATTACK VECTOR SOURCE_PORT
            if type(attack_vector['source_port']) == int:
                LOGGER.debug('Adding source ports')
                ddos.add_attribute('src-port', attack_vector['source_port'], comment='src-port')

            # ATTACK VECTOR DESTINATION PORTS
            if type(attack_vector['destination_ports']) == dict:
                LOGGER.debug('Adding destination ports')
                for port in attack_vector['destination_ports'].keys():
                    ddos.add_attribute('dst-port', int(port),
                                       comment='fraction={}'.format(attack_vector['destination_ports'][port]))

            # ATTACK VECTOR DNS
            if 'dns_query_name' in attack_vector or 'dns_query_type' in attack_vector:
                ddos.add_attribute('type', 'dns', comment='type of attack vector')
                ddos.add_attribute('type', 'dns-amplification', comment='type of attack vector')

            # ATTACK VECTOR ICMP
            if 'ICMP type' in attack_vector:
                ddos.add_attribute('type', 'icmp', comment='type of attack vector')

            # ATTACK VECTOR NTP
            if 'ntp_requestcode' in attack_vector:
                ddos.add_attribute('type', 'ntp-amplification', comment='type of attack vector')

            # ATTACK VECTOR SOURCE IPS
            if 'source_ips' in attack_vector and source_ips_limit > 0:
                for src_ip, i in zip(attack_vector['source_ips'], range(len(attack_vector['source_ips']))):
                    ddos.add_attribute('ip-src', src_ip, comment='source IP list truncated')
                    if i >= source_ips_limit-1:
                        break

            event.add_object(ddos, pythonify=True)

        event.publish()
        # event = misp.add_event(event, pythonify=True)
        event = misp.add_event(event, pythonify=True)

        result = add_misp_tag_to_event(host, token, protocol, noverify, event.id, ddosch_tag['Tag']['id'])
        LOGGER.debug(result)
        LOGGER.debug("That took {} seconds".format(time.time() - start))
    except Exception as e:
        LOGGER.error(e)
        raise
