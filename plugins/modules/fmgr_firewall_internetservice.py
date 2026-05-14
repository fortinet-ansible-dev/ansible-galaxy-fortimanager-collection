#!/usr/bin/python
from __future__ import absolute_import, division, print_function
# Copyright 2019-2024 Fortinet, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

__metaclass__ = type

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'metadata_version': '1.1'}

DOCUMENTATION = '''
---
module: fmgr_firewall_internetservice
short_description: Show Internet Service application.
version_added: "2.0.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.partial_crud
options:
    revision_note:
        description: The change note that can be specified when an object is created or updated.
        type: str
    adom:
        description: The parameter (adom) in requested url.
        type: str
        required: true
    firewall_internetservice:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            database:
                type: str
                description: Database.
                choices: ['isdb', 'irdb']
            direction:
                type: str
                description: Direction.
                choices: ['src', 'dst', 'both']
            entry:
                type: list
                elements: dict
                description: Entry.
                suboptions:
                    id:
                        type: int
                        description: Entry ID.
                    ip_number:
                        aliases: ['ip-number']
                        type: int
                        description: Total number of IP addresses.
                    ip_range_number:
                        aliases: ['ip-range-number']
                        type: int
                        description: Total number of IP ranges.
                    port:
                        type: raw
                        description: (list) Integer value for the TCP/IP port
                    protocol:
                        type: int
                        description: Integer value for the protocol type as defined by IANA
            icon_id:
                aliases: ['icon-id']
                type: int
                description: Icon id.
            id:
                type: int
                description: Id.
            name:
                type: str
                description: Name.
            offset:
                type: int
                description: Offset.
            reputation:
                type: int
                description: Reputation.
            sld_id:
                aliases: ['sld-id']
                type: int
                description: Sld id.
            extra_ip_range_number:
                aliases: ['extra-ip-range-number']
                type: int
                description: Extra ip range number.
            ip_number:
                aliases: ['ip-number']
                type: int
                description: Ip number.
            ip_range_number:
                aliases: ['ip-range-number']
                type: int
                description: Ip range number.
            jitter_threshold:
                aliases: ['jitter-threshold']
                type: int
                description: Jitter threshold.
            latency_threshold:
                aliases: ['latency-threshold']
                type: int
                description: Latency threshold.
            obsolete:
                type: int
                description: Obsolete.
            packetloss_threshold:
                aliases: ['packetloss-threshold']
                type: int
                description: Packetloss threshold.
            singularity:
                type: int
                description: Singularity.
            city:
                type: raw
                description: (list) City sequence number list.
            country:
                type: raw
                description: (list) Country sequence number list.
            region:
                type: raw
                description: (list) Region sequence number list.
            city6:
                type: raw
                description: (list) IPv6 City sequence number list.
            country6:
                type: raw
                description: (list) IPv6 Country sequence number list.
            extra_ip6_range_number:
                aliases: ['extra-ip6-range-number']
                type: int
                description: Extra ip6 range number.
            ip6_range_number:
                aliases: ['ip6-range-number']
                type: int
                description: Ip6 range number.
            region6:
                type: raw
                description: (list) IPv6 Region sequence number list.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Show Internet Service application.
      fortinet.fortimanager.fmgr_firewall_internetservice:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        firewall_internetservice:
          # database: <value in [isdb, irdb]>
          # direction: <value in [src, dst, both]>
          # entry:
          #   - id: <integer>
          #     ip_number: <integer>
          #     ip_range_number: <integer>
          #     port: <list or integer>
          #     protocol: <integer>
          # icon_id: <integer>
          # id: <integer>
          # name: <string>
          # offset: <integer>
          # reputation: <integer>
          # sld_id: <integer>
          # extra_ip_range_number: <integer>
          # ip_number: <integer>
          # ip_range_number: <integer>
          # jitter_threshold: <integer>
          # latency_threshold: <integer>
          # obsolete: <integer>
          # packetloss_threshold: <integer>
          # singularity: <integer>
          # city: <list or integer>
          # country: <list or integer>
          # region: <list or integer>
          # city6: <list or integer>
          # country6: <list or integer>
          # extra_ip6_range_number: <integer>
          # ip6_range_number: <integer>
          # region6: <list or integer>
'''

RETURN = '''
meta:
    description: The result of the request.
    type: dict
    returned: always
    contains:
        request_url:
            description: The full url requested.
            returned: always
            type: str
            sample: /sys/login/user
        response_code:
            description: The status of api request.
            returned: always
            type: int
            sample: 0
        response_data:
            description: The api response.
            type: list
            returned: always
        response_message:
            description: The descriptive message of the api response.
            type: str
            returned: always
            sample: OK.
        system_information:
            description: The information of the target system.
            type: dict
            returned: always
rc:
    description: The status the request.
    type: int
    returned: always
    sample: 0
version_check_warning:
    description: Warning if the parameters used in the playbook are not supported by the current FortiManager version.
    type: list
    returned: complex
'''
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import NAPIManager, check_galaxy_version, check_parameter_bypass
from ansible_collections.fortinet.fortimanager.plugins.module_utils.common import get_module_arg_spec


def main():
    urls_list = [
        '/pm/config/adom/{adom}/obj/firewall/internet-service',
        '/pm/config/global/obj/firewall/internet-service'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'firewall_internetservice': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'database': {'choices': ['isdb', 'irdb'], 'type': 'str'},
                'direction': {'choices': ['src', 'dst', 'both'], 'type': 'str'},
                'entry': {
                    'v_range': [['6.0.0', '7.2.1'], ['7.4.8', '7.4.10']],
                    'type': 'list',
                    'options': {
                        'id': {'v_range': [['6.0.0', '7.2.1'], ['7.4.8', '7.4.10']], 'type': 'int'},
                        'ip-number': {'v_range': [['6.0.0', '7.2.1'], ['7.4.8', '7.4.10']], 'type': 'int'},
                        'ip-range-number': {'v_range': [['6.0.0', '7.2.1'], ['7.4.8', '7.4.10']], 'type': 'int'},
                        'port': {'v_range': [['6.0.0', '7.2.1'], ['7.4.8', '7.4.10']], 'type': 'raw'},
                        'protocol': {'v_range': [['6.0.0', '7.2.1'], ['7.4.8', '7.4.10']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'icon-id': {'type': 'int'},
                'id': {'type': 'int'},
                'name': {'type': 'str'},
                'offset': {'v_range': [['6.0.0', '7.2.1'], ['7.4.8', '7.4.10']], 'type': 'int'},
                'reputation': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                'sld-id': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                'extra-ip-range-number': {'v_range': [['6.2.0', '']], 'type': 'int'},
                'ip-number': {'v_range': [['6.2.0', '']], 'type': 'int'},
                'ip-range-number': {'v_range': [['6.2.0', '']], 'type': 'int'},
                'jitter-threshold': {'v_range': [['6.2.0', '7.2.0']], 'type': 'int'},
                'latency-threshold': {'v_range': [['6.2.0', '7.2.0']], 'type': 'int'},
                'obsolete': {'v_range': [['6.2.0', '']], 'type': 'int'},
                'packetloss-threshold': {'v_range': [['6.2.0', '7.2.0']], 'type': 'int'},
                'singularity': {'v_range': [['6.2.0', '']], 'type': 'int'},
                'city': {'v_range': [['6.4.0', '7.2.5'], ['7.4.0', '7.4.2']], 'type': 'raw'},
                'country': {'v_range': [['6.4.0', '7.2.5'], ['7.4.0', '7.4.2']], 'type': 'raw'},
                'region': {'v_range': [['6.4.0', '7.2.5'], ['7.4.0', '7.4.2']], 'type': 'raw'},
                'city6': {'v_range': [['7.2.1', '7.2.5'], ['7.4.0', '7.4.2']], 'type': 'raw'},
                'country6': {'v_range': [['7.2.1', '7.2.5'], ['7.4.0', '7.4.2']], 'type': 'raw'},
                'extra-ip6-range-number': {'v_range': [['7.2.1', '']], 'type': 'int'},
                'ip6-range-number': {'v_range': [['7.2.1', '']], 'type': 'int'},
                'region6': {'v_range': [['7.2.1', '7.2.5'], ['7.4.0', '7.4.2']], 'type': 'raw'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_internetservice'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('partial crud', module_arg_spec, urls_list,
                       None, 'data', module, connection)
    fmgr.process_partial_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
