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
module: fmgr_switchcontroller_acl_ingress_classifier
short_description: ACL classifiers.
version_added: "2.2.0"
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
    ingress:
        description: The parameter (ingress) in requested url.
        type: str
        required: true
    switchcontroller_acl_ingress_classifier:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            dst_ip_prefix:
                aliases: ['dst-ip-prefix']
                type: str
                description: Destination IP address to be matched.
            dst_mac:
                aliases: ['dst-mac']
                type: str
                description: Destination MAC address to be matched.
            src_ip_prefix:
                aliases: ['src-ip-prefix']
                type: str
                description: Source IP address to be matched.
            src_mac:
                aliases: ['src-mac']
                type: str
                description: Source MAC address to be matched.
            vlan:
                type: int
                description: VLAN ID to be matched.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: ACL classifiers.
      fortinet.fortimanager.fmgr_switchcontroller_acl_ingress_classifier:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        ingress: <your own value>
        switchcontroller_acl_ingress_classifier:
          # dst_ip_prefix: <string>
          # dst_mac: <string>
          # src_ip_prefix: <string>
          # src_mac: <string>
          # vlan: <integer>
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
        '/pm/config/adom/{adom}/obj/switch-controller/acl/ingress/{ingress}/classifier',
        '/pm/config/global/obj/switch-controller/acl/ingress/{ingress}/classifier'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'ingress': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'switchcontroller_acl_ingress_classifier': {
            'type': 'dict', 'v_range': [['7.4.0', '']],
            'options': {
                'dst-ip-prefix': {'v_range': [['7.4.0', '']], 'type': 'str'},
                'dst-mac': {'v_range': [['7.4.0', '']], 'type': 'str'},
                'src-ip-prefix': {'v_range': [['7.4.0', '']], 'type': 'str'},
                'src-mac': {'v_range': [['7.4.0', '']], 'type': 'str'},
                'vlan': {'v_range': [['7.4.0', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'switchcontroller_acl_ingress_classifier'),
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
