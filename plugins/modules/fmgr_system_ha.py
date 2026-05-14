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
module: fmgr_system_ha
short_description: HA configuration.
version_added: "1.0.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.partial_crud
options:
    system_ha:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            clusterid:
                type: int
                description: Cluster ID range
            file_quota:
                aliases: ['file-quota']
                type: int
                description: File quota in MB
            hb_interval:
                aliases: ['hb-interval']
                type: int
                description: Heartbeat interval
            hb_lost_threshold:
                aliases: ['hb-lost-threshold']
                type: int
                description: Heartbeat lost threshold
            mode:
                type: str
                description:
                    - Mode.
                    - standalone - Standalone.
                    - master - Master.
                    - slave - Slave.
                choices: ['standalone', 'master', 'slave', 'primary', 'secondary']
            password:
                type: raw
                description: (list) Group password.
            peer:
                type: list
                elements: dict
                description: Peer.
                suboptions:
                    id:
                        type: int
                        description: Id.
                    ip:
                        type: str
                        description: IP address of peer.
                    ip6:
                        type: str
                        description: IP address
                    serial_number:
                        aliases: ['serial-number']
                        type: str
                        description: Serial number of peer.
                    status:
                        type: str
                        description:
                            - Peer admin status.
                            - disable - Disable.
                            - enable - Enable.
                        choices: ['disable', 'enable']
            local_cert:
                aliases: ['local-cert']
                type: str
                description: Set the ha local certificate.
            failover_mode:
                aliases: ['failover-mode']
                type: str
                description:
                    - HA failover mode.
                    - manual - Manual Failove
                    - vrrp - Use VRRP
                choices: ['manual', 'vrrp']
            monitored_interfaces:
                aliases: ['monitored-interfaces']
                type: list
                elements: dict
                description: Monitored interfaces.
                suboptions:
                    interface_name:
                        aliases: ['interface-name']
                        type: str
                        description: Interface name.
            monitored_ips:
                aliases: ['monitored-ips']
                type: list
                elements: dict
                description: Monitored ips.
                suboptions:
                    id:
                        type: int
                        description: Id.
                    interface:
                        type: str
                        description: Interface name.
                    ip:
                        type: str
                        description: IP address.
            priority:
                type: int
                description: Runtime priority [1
            unicast:
                type: str
                description:
                    - Use unitcast for VRRP message.
                    - disable - Disable.
                    - enable - Enable.
                choices: ['disable', 'enable']
            vip:
                type: str
                description: Virtual IP.
            vrrp_adv_interval:
                aliases: ['vrrp-adv-interval']
                type: int
                description: VRRP advert interval [1 - 30 seconnds]
            vrrp_interface:
                aliases: ['vrrp-interface']
                type: str
                description: VRRP and vip interface.
            vip_interface:
                aliases: ['vip-interface']
                type: str
                description: Vip interface.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: HA configuration.
      fortinet.fortimanager.fmgr_system_ha:
        # workspace_locking_adom: <global or your adom name>
        system_ha:
          # clusterid: <integer>
          # file_quota: <integer>
          # hb_interval: <integer>
          # hb_lost_threshold: <integer>
          # mode: <value in [standalone, master, slave, ...]>
          # password: <list or string>
          # peer:
          #   - id: <integer>
          #     ip: <string>
          #     ip6: <string>
          #     serial_number: <string>
          #     status: <value in [disable, enable]>
          # local_cert: <string>
          # failover_mode: <value in [manual, vrrp]>
          # monitored_interfaces:
          #   - interface_name: <string>
          # monitored_ips:
          #   - id: <integer>
          #     interface: <string>
          #     ip: <string>
          # priority: <integer>
          # unicast: <value in [disable, enable]>
          # vip: <string>
          # vrrp_adv_interval: <integer>
          # vrrp_interface: <string>
          # vip_interface: <string>
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
        '/cli/global/system/ha'
    ]
    module_arg_spec = {
        'system_ha': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'clusterid': {'type': 'int'},
                'file-quota': {'type': 'int'},
                'hb-interval': {'type': 'int'},
                'hb-lost-threshold': {'type': 'int'},
                'mode': {'choices': ['standalone', 'master', 'slave', 'primary', 'secondary'], 'type': 'str'},
                'password': {'no_log': True, 'type': 'raw'},
                'peer': {
                    'type': 'list',
                    'options': {
                        'id': {'type': 'int'},
                        'ip': {'type': 'str'},
                        'ip6': {'type': 'str'},
                        'serial-number': {'type': 'str'},
                        'status': {'choices': ['disable', 'enable'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'local-cert': {'v_range': [['6.2.7', '']], 'type': 'str'},
                'failover-mode': {'v_range': [['7.2.0', '']], 'choices': ['manual', 'vrrp'], 'type': 'str'},
                'monitored-interfaces': {
                    'v_range': [['7.2.0', '']],
                    'type': 'list',
                    'options': {'interface-name': {'v_range': [['7.2.0', '']], 'type': 'str'}},
                    'elements': 'dict'
                },
                'monitored-ips': {
                    'v_range': [['7.2.0', '']],
                    'type': 'list',
                    'options': {
                        'id': {'v_range': [['7.2.0', '']], 'type': 'int'},
                        'interface': {'v_range': [['7.2.0', '']], 'type': 'str'},
                        'ip': {'v_range': [['7.2.0', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'priority': {'v_range': [['7.2.0', '']], 'type': 'int'},
                'unicast': {'v_range': [['7.2.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'vip': {'v_range': [['7.2.0', '']], 'type': 'str'},
                'vrrp-adv-interval': {'v_range': [['7.2.0', '']], 'type': 'int'},
                'vrrp-interface': {'v_range': [['7.2.0', '']], 'type': 'str'},
                'vip-interface': {'v_range': [['7.2.4', '7.2.12'], ['7.4.1', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_ha'),
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
