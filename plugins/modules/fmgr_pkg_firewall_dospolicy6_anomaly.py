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
module: fmgr_pkg_firewall_dospolicy6_anomaly
short_description: Anomaly name.
version_added: "2.0.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.full_crud
options:
    revision_note:
        description: The change note that can be specified when an object is created or updated.
        type: str
    adom:
        description: The parameter (adom) in requested url.
        type: str
        required: true
    pkg:
        description: The parameter (pkg) in requested url.
        type: str
        required: true
    DoS-policy6:
        description: Deprecated, please use "DoS_policy6"
        type: str
    DoS_policy6:
        description: The parameter (DoS-policy6) in requested url.
        type: str
    pkg_firewall_dospolicy6_anomaly:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            action:
                type: str
                description: Action taken when the threshold is reached.
                choices: ['pass', 'block', 'proxy']
            log:
                type: str
                description: Enable/disable logging for this anomaly.
                choices: ['disable', 'enable']
            name:
                type: str
                description: Anomaly name.
                required: true
            quarantine:
                type: str
                description: Quarantine method.
                choices: ['none', 'attacker', 'both', 'interface']
            quarantine_expiry:
                aliases: ['quarantine-expiry']
                type: str
                description: Duration of quarantine, from 1 minute to 364 days, 23 hours, and 59 minutes from now.
            quarantine_log:
                aliases: ['quarantine-log']
                type: str
                description: Enable/disable quarantine logging.
                choices: ['disable', 'enable']
            status:
                type: str
                description: Enable/disable the active status of this anomaly sensor.
                choices: ['disable', 'enable']
            threshold:
                type: int
                description: Number of detected instances per minute which triggers action
            threshold_default:
                aliases: ['threshold(default)']
                type: int
                description: Threshold
            synproxy_tos:
                type: str
                description: Determine TCP differentiated services code point value
                choices: ['0', '10', '12', '14', '18', '20', '22', '26', '28', '30', '34', '36',
                          '38', '40', '46', '255']
            synproxy_ttl:
                type: str
                description: Determine Time to live
                choices: ['32', '64', '128', '255']
            synproxy_tcp_sack:
                type: str
                description: Enable/disable TCP selective acknowledage
                choices: ['disable', 'enable']
            synproxy_tcp_window:
                type: str
                description: Determine TCP Window size for packets replied by syn proxy module.
                choices: ['4096', '8192', '16384', '32768']
            synproxy_tcp_timestamp:
                type: str
                description: Enable/disable TCP timestamp option for packets replied by syn proxy module.
                choices: ['disable', 'enable']
            synproxy_tcp_mss:
                type: str
                description: Determine TCP maximum segment size
                choices: ['0', '256', '512', '1024', '1300', '1360', '1460', '1500']
            synproxy_tcp_windowscale:
                type: str
                description: Determine TCP window scale option value for packets replied by syn proxy module.
                choices: ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12',
                          '13', '14']
            synproxy-tos:
                type: str
                description: Deprecated, please rename it to synproxy_tos. Determine TCP differentiated services code point value
                choices: ['0', '10', '12', '14', '18', '20', '22', '26', '28', '30', '34', '36',
                          '38', '40', '46', '255']
            synproxy-tcp-window:
                type: str
                description: Deprecated, please rename it to synproxy_tcp_window. Determine TCP Window size for packets replied by syn proxy module.
                choices: ['4096', '8192', '16384', '32768']
            synproxy-tcp-windowscale:
                type: str
                description: Deprecated, please rename it to synproxy_tcp_windowscale. Determine TCP window scale option value for packets replied by s...
                choices: ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12',
                          '13', '14']
            synproxy-tcp-timestamp:
                type: str
                description: Deprecated, please rename it to synproxy_tcp_timestamp. Enable/disable TCP timestamp option for packets replied by syn pro...
                choices: ['disable', 'enable']
            synproxy-ttl:
                type: str
                description: Deprecated, please rename it to synproxy_ttl. Determine Time to live
                choices: ['32', '64', '128', '255']
            synproxy-tcp-mss:
                type: str
                description: Deprecated, please rename it to synproxy_tcp_mss. Determine TCP maximum segment size
                choices: ['0', '256', '512', '1024', '1300', '1360', '1460', '1500']
            synproxy-tcp-sack:
                type: str
                description: Deprecated, please rename it to synproxy_tcp_sack. Enable/disable TCP selective acknowledage
                choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Anomaly name.
      fortinet.fortimanager.fmgr_pkg_firewall_dospolicy6_anomaly:
        bypass_validation: false
        adom: ansible
        pkg: ansible # package name
        DoS_policy6: 1 # policyid
        state: present
        pkg_firewall_dospolicy6_anomaly:
          action: pass # <value in [pass, block, proxy]>
          log: enable
          name: "ansible-test-anomaly6"
          quarantine: attacker # <value in [none, attacker, both, ...]>
          status: enable

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the anomaly names of IPv6 DoS policy
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "pkg_firewall_dospolicy6_anomaly"
          params:
            adom: "ansible"
            pkg: "ansible" # package name
            DoS_policy6: "1" # policyid
            anomaly: "your_value"
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
        '/pm/config/adom/{adom}/pkg/{pkg}/firewall/DoS-policy6/{DoS-policy6}/anomaly'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'pkg': {'required': True, 'type': 'str'},
        'DoS-policy6': {'type': 'str', 'api_name': 'DoS_policy6'},
        'DoS_policy6': {'type': 'str'},
        'revision_note': {'type': 'str'},
        'pkg_firewall_dospolicy6_anomaly': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'action': {'choices': ['pass', 'block', 'proxy'], 'type': 'str'},
                'log': {'choices': ['disable', 'enable'], 'type': 'str'},
                'name': {'required': True, 'type': 'str'},
                'quarantine': {'choices': ['none', 'attacker', 'both', 'interface'], 'type': 'str'},
                'quarantine-expiry': {'type': 'str'},
                'quarantine-log': {'choices': ['disable', 'enable'], 'type': 'str'},
                'status': {'choices': ['disable', 'enable'], 'type': 'str'},
                'threshold': {'type': 'int'},
                'threshold(default)': {'type': 'int'},
                'synproxy_tos': {
                    'v_range': [['6.2.5', '7.2.0']],
                    'choices': ['0', '10', '12', '14', '18', '20', '22', '26', '28', '30', '34', '36', '38', '40', '46', '255'],
                    'type': 'str'
                },
                'synproxy_ttl': {'v_range': [['6.2.5', '7.2.0']], 'choices': ['32', '64', '128', '255'], 'type': 'str'},
                'synproxy_tcp_sack': {'v_range': [['6.2.5', '7.2.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'synproxy_tcp_window': {'v_range': [['6.2.5', '7.2.0']], 'choices': ['4096', '8192', '16384', '32768'], 'type': 'str'},
                'synproxy_tcp_timestamp': {'v_range': [['6.2.5', '7.2.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'synproxy_tcp_mss': {
                    'v_range': [['6.2.5', '7.2.0']],
                    'choices': ['0', '256', '512', '1024', '1300', '1360', '1460', '1500'],
                    'type': 'str'
                },
                'synproxy_tcp_windowscale': {
                    'v_range': [['6.2.5', '7.2.0']],
                    'choices': ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14'],
                    'type': 'str'
                },
                'synproxy-tos': {
                    'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '7.2.0'], ['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'choices': ['0', '10', '12', '14', '18', '20', '22', '26', '28', '30', '34', '36', '38', '40', '46', '255'],
                    'type': 'str'
                },
                'synproxy-tcp-window': {
                    'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '7.2.0'], ['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'choices': ['4096', '8192', '16384', '32768'],
                    'type': 'str'
                },
                'synproxy-tcp-windowscale': {
                    'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '7.2.0'], ['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'choices': ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14'],
                    'type': 'str'
                },
                'synproxy-tcp-timestamp': {
                    'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '7.2.0'], ['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'choices': ['disable', 'enable'],
                    'type': 'str'
                },
                'synproxy-ttl': {
                    'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '7.2.0'], ['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'choices': ['32', '64', '128', '255'],
                    'type': 'str'
                },
                'synproxy-tcp-mss': {
                    'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '7.2.0'], ['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'choices': ['0', '256', '512', '1024', '1300', '1360', '1460', '1500'],
                    'type': 'str'
                },
                'synproxy-tcp-sack': {
                    'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '7.2.0'], ['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'choices': ['disable', 'enable'],
                    'type': 'str'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'pkg_firewall_dospolicy6_anomaly'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('full crud', module_arg_spec, urls_list,
                       'name', 'data', module, connection)
    fmgr.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
