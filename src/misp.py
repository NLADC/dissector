import requests
import urllib3
import json
import time
from pymisp import ExpandedPyMISP, MISPEvent, MISPObject
from pymisp.exceptions import PyMISPError
from typing import Optional

from logger import LOGGER

__all__ = ['MispInstance']


class MispInstance:
    ddosch_tag_name = 'DDoSCH'
    ddosch_tag_colour = '#ff7dfd'

    def __init__(self, host: str, token: str, protocol: str, verify_tls: bool, sharing_group: str, publish: bool = False):
        self.host = host
        self.token = token
        self.protocol = protocol
        self.verify_tls = verify_tls
        self.misp: ExpandedPyMISP
        self.sharing_group = sharing_group
        self.publish = publish

        try:
            self.misp = ExpandedPyMISP(f'{self.protocol}://{self.host}', self.token, ssl=self.verify_tls,
                                       tool='dissector')
        except PyMISPError:
            LOGGER.critical(f'Could not connect to MISP instance at "{self.protocol}://{self.host}".')
            self.misp = None

    def search_misp_events(self, misp_filter: dict = None) -> Optional[dict]:
        """
        Search for MISP events
        :param misp_filter: fields by which to filter retrieved MISP events
        :return: MISP events if found, else None
        """
        LOGGER.debug(f'Searching MISP events with filter: {misp_filter}')

        if not self.verify_tls:
            urllib3.disable_warnings()

        response = requests.post(f'{self.protocol}://{self.host}/events/index',
                                 json=misp_filter or dict(),
                                 headers={'Authorization': self.token,
                                          'Accept': 'application/json'},
                                 timeout=10, verify=self.verify_tls)

        try:
            response.raise_for_status()
            return response.json()
        except requests.HTTPError:
            LOGGER.critical(f'Retrieving MISP events responded with status code:{response.status_code}')
            return None

    def get_misp_tag(self, tag_name) -> Optional[dict]:
        """
        Search in MISP for a tag with tag_name, return the tag dict if it exists.
        :param tag_name: Name of the tag to retrieve
        :return: Tag or None
        """
        LOGGER.info(f'Searching for {tag_name} tag in MISP')

        if not self.verify_tls:
            urllib3.disable_warnings()
        response = requests.get(f'{self.protocol}://{self.host}/tags/search/{self.ddosch_tag_name}',
                                headers={'Authorization': self.token,
                                         'Accept': 'application/json'},
                                timeout=10, verify=self.verify_tls)
        try:
            response.raise_for_status()
            for item in response.json():
                if item['Tag']['name'] == self.ddosch_tag_name:
                    return item
            else:
                LOGGER.info(f'No tags found with name "{self.ddosch_tag_name}"')
                return None
        except requests.HTTPError:
            LOGGER.critical(f'Searching for MISP Tag responded with status code:{response.status_code}')
            return None

    def add_misp_tag(self, tag_name, tag_color) -> Optional[dict]:
        """
        Create a new tag in MISP
        :param tag_name: Name of the new tag
        :param tag_color: Color of the new tag
        :return: Server response if succesful, else None
        """
        LOGGER.debug(f'Creating a {tag_name} tag in MISP')

        if not self.verify_tls:
            urllib3.disable_warnings()
        response = requests.post(f'{self.protocol}://{self.host}/tags/add',
                                 json={'name': tag_name, 'colour': tag_color},
                                 headers={'Authorization': self.token,
                                          'Accept': 'application/json'},
                                 timeout=10, verify=self.verify_tls)
        try:
            response.raise_for_status()
            return response.json()
        except requests.HTTPError:
            LOGGER.critical(f'Creating MISP Tag responded with status code:{response.status_code}')
            return None

    def add_misp_fingerprint(self, fingerprint_json: dict):
        """
        Upload fingerprint to MISP
        :param fingerprint_json: fingerprint to upload
        :return:
        """

        LOGGER.info('Uploading the fingerprint to MISP')
        start = time.time()

        # Maximum number of source IPs to include
        # 0 means all (no limit)
        source_ips_limit = 10

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
            'time_end',
            'duration_seconds',
            'total_flows',
            'total_megabytes',
            'total_packets',
            'total_ips',
            'avg_bps',
            'avg_pps',
            'avg_Bpp',
        ]

        # Create the DDoSCH tag (returns existing one if already present)
        ddosch_tag = self.get_misp_tag(self.ddosch_tag_name)
        if ddosch_tag is None:
            ddosch_tag = self.add_misp_tag(self.ddosch_tag_name, self.ddosch_tag_colour)
        LOGGER.debug(ddosch_tag)

        # Retrieve (or create) the sharing group if specified
        misp_sharing_group = None
        if self.sharing_group:
            misp_sharing_group = [sh_grp for sh_grp in self.misp.sharing_groups(pythonify=True) if
                                  sh_grp.name == self.sharing_group]
            if len(misp_sharing_group) == 0:
                misp_sharing_group = self.misp.add_sharing_group({'name': self.sharing_group}, pythonify=True)
            else:
                misp_sharing_group = misp_sharing_group[0]

        # Create an event to link everything to
        LOGGER.debug('Creating a new event for the fingerprint')
        event = MISPEvent()
        event.info = fingerprint_json['key']

        # TARGET
        event.add_attribute(category='Network activity',
                            type='ip-dst',
                            value=fingerprint_json['target'],
                            comment='target')
        # KEY
        event.add_attribute(category='Network activity',
                            type='md5',
                            value=fingerprint_json['key'],
                            comment='attack key')

        LOGGER.debug('Adding fingerprint fields')
        for fp_field in fingerprint_fields:
            if fp_field in fingerprint_json:
                event.add_attribute(category='Network activity',
                                    type='comment',
                                    value=fingerprint_json[fp_field],
                                    comment=fp_field)

        # TAGS
        if 'tags' in fingerprint_json:
            LOGGER.debug('Adding fingerprint tags')
            for tag in fingerprint_json['tags']:
                event.add_tag(tag=tag)
        event.add_tag(tag='validated')
        if ddosch_tag is not None:
            event.add_tag(tag=self.ddosch_tag_name)

        # Add each attack vector as a MISP object to the MISP event
        for v_i, attack_vector in enumerate(fingerprint_json['attack_vectors']):
            LOGGER.debug(f'Processing Attack Vector #{v_i}')
            ddos_object = MISPObject(name='ddos')
            # ATTACK VECTOR PROTOCOL
            ddos_object.add_attribute('protocol',
                                      attack_vector['protocol'],
                                      comment=f'vector {v_i}')

            for av_dict in attack_vector_dicts:
                if av_dict in attack_vector and type(attack_vector[av_dict]) == dict:
                    LOGGER.debug(f'Adding dict {av_dict}')
                    event.add_attribute(category='Network activity', type='comment',
                                        value=json.dumps(attack_vector[av_dict]),
                                        comment=f'vector {v_i} {av_dict} ({av_dict}:fraction)')

            for av_field in attack_vector_fields:
                if av_field in attack_vector and attack_vector[av_field] is not None:
                    LOGGER.debug(f'Adding field {av_field}')
                    event.add_attribute(category='Network activity', type='comment',
                                        value=attack_vector[av_field],
                                        comment=f'vector {v_i} {av_field}')

            # ATTACK VECTOR SOURCE_PORT
            if type(attack_vector['source_port']) == int:
                LOGGER.debug('Adding source ports')
                ddos_object.add_attribute('src-port', attack_vector['source_port'], comment=f'vector {v_i} src-port')

            # ATTACK VECTOR DESTINATION PORTS
            if type(attack_vector['destination_ports']) == dict:
                LOGGER.debug('Adding destination ports')
                for port in attack_vector['destination_ports'].keys():
                    ddos_object.add_attribute('dst-port', int(port),
                                              comment=f'vector {v_i} destination port '
                                                      f'(fraction:{attack_vector["destination_ports"][port]}')

            # ATTACK VECTOR DNS
            if 'dns_query_name' in attack_vector or 'dns_query_type' in attack_vector:
                ddos_object.add_attribute('type', 'dns', comment=f'vector {v_i}  type of attack vector')
                ddos_object.add_attribute('type', 'dns-amplification', comment=f'vector {v_i} type of attack vector')

            # ATTACK VECTOR ICMP
            if 'ICMP type' in attack_vector:
                ddos_object.add_attribute('type', 'icmp', comment=f'vector {v_i} type of attack vector')

            # ATTACK VECTOR NTP
            if 'ntp_requestcode' in attack_vector:
                ddos_object.add_attribute('type', 'ntp-amplification', comment=f'vector {v_i} type of attack vector')

            # ATTACK VECTOR SOURCE IPS
            if 'source_ips' in attack_vector:
                for i, src_ip in enumerate(attack_vector['source_ips'], start=1):
                    ddos_object.add_attribute('ip-src', src_ip, comment=f'vector {v_i}  source IP')
                    if i >= source_ips_limit > 0:
                        break

            event.add_object(ddos_object, pythonify=True)

        if self.publish:
            event.publish()

        event = self.misp.add_event(event, pythonify=True)

        if misp_sharing_group:
            self.misp.change_sharing_group_on_entity(event, misp_sharing_group.id, pythonify=True)

        LOGGER.info(f'event: {event}')

        LOGGER.debug('That took {} seconds'.format(time.time() - start))
