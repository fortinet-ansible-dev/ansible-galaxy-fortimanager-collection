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
module: fmgr_system_dhcp_template_iprange
short_description: DHCP IP range configuration.
version_added: "2.16.0"
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
  template:
    description: The parameter (template) in requested url.
    type: str
    required: true
  system_dhcp_template_iprange:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      id:
        type: int
        description: ID.
        required: true
      ip_count:
        aliases: ['ip-count']
        type: int
        description: Number of IP addresses to include in the range.
      lease_time:
        aliases: ['lease-time']
        type: int
        description: Lease time in seconds, 0 means default lease time.
      oui_match:
        aliases: ['oui-match']
        type: str
        description: Enable/disable organizationally unique identifier
        choices: ['disable', 'enable']
      oui_string:
        aliases: ['oui-string']
        type: list
        elements: str
        description: One or more OUI strings in quotes separated by spaces
      reserve:
        type: str
        description: Enable/disable address reservation for use without DHCP.
        choices: ['disable', 'enable']
      uci_match:
        aliases: ['uci-match']
        type: str
        description: Enable/disable user class identifier
        choices: ['disable', 'enable']
      uci_string:
        aliases: ['uci-string']
        type: list
        elements: str
        description: One or more UCI strings in quotes separated by spaces.
      vci_match:
        aliases: ['vci-match']
        type: str
        description: Enable/disable vendor class identifier
        choices: ['disable', 'enable']
      vci_string:
        aliases: ['vci-string']
        type: list
        elements: str
        description: One or more VCI strings in quotes separated by spaces.
      vendor:
        type: str
        description: Vendor this ip-range will be assigned to.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: DHCP IP range configuration.
      fortinet.fortimanager.fmgr_system_dhcp_template_iprange:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        template: <your own value>
        state: present # <value in [present, absent]>
        system_dhcp_template_iprange:
          id: 0 # Required variable, integer
          # ip_count: <integer>
          # lease_time: <integer>
          # oui_match: <value in [disable, enable]>
          # oui_string: <list or string>
          # reserve: <value in [disable, enable]>
          # uci_match: <value in [disable, enable]>
          # uci_string: <list or string>
          # vci_match: <value in [disable, enable]>
          # vci_string: <list or string>
          # vendor: <string>
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
        '/pm/config/adom/{adom}/obj/system/dhcp/template/{template}/ip-range',
        '/pm/config/global/obj/system/dhcp/template/{template}/ip-range'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'template': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'system_dhcp_template_iprange': {
            'type': 'dict', 'v_range': [['8.0.1', '']],
            'options': {
                'id': {'v_range': [['8.0.1', '']], 'required': True, 'type': 'int'},
                'ip-count': {'v_range': [['8.0.1', '']], 'type': 'int'},
                'lease-time': {'v_range': [['8.0.1', '']], 'type': 'int'},
                'oui-match': {'v_range': [['8.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'oui-string': {'v_range': [['8.0.1', '']], 'type': 'list', 'elements': 'str'},
                'reserve': {'v_range': [['8.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'uci-match': {'v_range': [['8.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'uci-string': {'v_range': [['8.0.1', '']], 'type': 'list', 'elements': 'str'},
                'vci-match': {'v_range': [['8.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'vci-string': {'v_range': [['8.0.1', '']], 'type': 'list', 'elements': 'str'},
                'vendor': {'v_range': [['8.0.1', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_dhcp_template_iprange'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('full crud', module_arg_spec, urls_list,
                       'id', 'data', module, connection)
    fmgr.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
