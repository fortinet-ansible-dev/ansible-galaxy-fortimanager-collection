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
module: fmgr_dnsfilter_profile_dnstranslation
short_description: DNS translation settings.
version_added: "2.1.0"
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
    profile:
        description: The parameter (profile) in requested url.
        type: str
        required: true
    dnsfilter_profile_dnstranslation:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            dst:
                type: str
                description: IPv4 address or subnet on the external network to substitute for the resolved address in DNS query replies.
            id:
                type: int
                description: ID.
                required: true
            netmask:
                type: str
                description: If src and dst are subnets rather than single IP addresses, enter the netmask for both src and dst.
            src:
                type: str
                description: IPv4 address or subnet on the internal network to compare with the resolved address in DNS query replies.
            status:
                type: str
                description: Enable/disable this DNS translation entry.
                choices: ['disable', 'enable']
            addr_type:
                aliases: ['addr-type']
                type: str
                description: DNS translation type
                choices: ['ipv4', 'ipv6']
            dst6:
                type: str
                description: IPv6 address or subnet on the external network to substitute for the resolved address in DNS query replies.
            prefix:
                type: int
                description: If src6 and dst6 are subnets rather than single IP addresses, enter the prefix for both src6 and dst6
            src6:
                type: str
                description: IPv6 address or subnet on the internal network to compare with the resolved address in DNS query replies.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: DNS translation settings.
      fortinet.fortimanager.fmgr_dnsfilter_profile_dnstranslation:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        profile: <your own value>
        state: present # <value in [present, absent]>
        dnsfilter_profile_dnstranslation:
          id: 0 # Required variable, integer
          # dst: <string>
          # netmask: <string>
          # src: <string>
          # status: <value in [disable, enable]>
          # addr_type: <value in [ipv4, ipv6]>
          # dst6: <string>
          # prefix: <integer>
          # src6: <string>
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
        '/pm/config/adom/{adom}/obj/dnsfilter/profile/{profile}/dns-translation',
        '/pm/config/global/obj/dnsfilter/profile/{profile}/dns-translation'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'profile': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'dnsfilter_profile_dnstranslation': {
            'type': 'dict', 'v_range': [['6.2.0', '']],
            'options': {
                'dst': {'v_range': [['6.2.0', '']], 'type': 'str'},
                'id': {'v_range': [['6.2.0', '']], 'required': True, 'type': 'int'},
                'netmask': {'v_range': [['6.2.0', '']], 'type': 'str'},
                'src': {'v_range': [['6.2.0', '']], 'type': 'str'},
                'status': {'v_range': [['6.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'addr-type': {'v_range': [['6.2.2', '']], 'choices': ['ipv4', 'ipv6'], 'type': 'str'},
                'dst6': {'v_range': [['6.2.2', '']], 'type': 'str'},
                'prefix': {'v_range': [['6.2.2', '']], 'type': 'int'},
                'src6': {'v_range': [['6.2.2', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'dnsfilter_profile_dnstranslation'),
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
