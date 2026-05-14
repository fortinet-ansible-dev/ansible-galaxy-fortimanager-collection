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
module: fmgr_firewall_accessproxyvirtualhost
short_description: Configure Access Proxy virtual hosts.
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
    firewall_accessproxyvirtualhost:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            host:
                type: str
                description: The host name.
            host_type:
                aliases: ['host-type']
                type: str
                description: Type of host pattern.
                choices: ['sub-string', 'wildcard']
            name:
                type: str
                description: Virtual host name.
                required: true
            ssl_certificate:
                aliases: ['ssl-certificate']
                type: str
                description: SSL certificate for this host.
            replacemsg_group:
                aliases: ['replacemsg-group']
                type: str
                description: Access-proxy-virtual-host replacement message override group.
            client_cert:
                aliases: ['client-cert']
                type: str
                description: Enable/disable requesting client certificate.
                choices: ['disable', 'enable']
            empty_cert_action:
                aliases: ['empty-cert-action']
                type: str
                description: Action for an empty client certificate.
                choices: ['block', 'accept', 'accept-unmanageable']
            user_agent_detect:
                aliases: ['user-agent-detect']
                type: str
                description: Enable/disable detecting device type by HTTP user-agent if no client certificate is provided.
                choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure Access Proxy virtual hosts.
      fortinet.fortimanager.fmgr_firewall_accessproxyvirtualhost:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        state: present # <value in [present, absent]>
        firewall_accessproxyvirtualhost:
          name: "your value" # Required variable, string
          # host: <string>
          # host_type: <value in [sub-string, wildcard]>
          # ssl_certificate: <string>
          # replacemsg_group: <string>
          # client_cert: <value in [disable, enable]>
          # empty_cert_action: <value in [block, accept, accept-unmanageable]>
          # user_agent_detect: <value in [disable, enable]>
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
        '/pm/config/adom/{adom}/obj/firewall/access-proxy-virtual-host',
        '/pm/config/global/obj/firewall/access-proxy-virtual-host'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'firewall_accessproxyvirtualhost': {
            'type': 'dict', 'v_range': [['7.0.1', '']],
            'options': {
                'host': {'v_range': [['7.0.1', '']], 'type': 'str'},
                'host-type': {'v_range': [['7.0.1', '']], 'choices': ['sub-string', 'wildcard'], 'type': 'str'},
                'name': {'v_range': [['7.0.1', '']], 'required': True, 'type': 'str'},
                'ssl-certificate': {'v_range': [['7.0.1', '']], 'type': 'str'},
                'replacemsg-group': {'v_range': [['7.0.5', '7.0.16'], ['7.2.1', '']], 'type': 'str'},
                'client-cert': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'empty-cert-action': {'v_range': [['7.6.2', '']], 'choices': ['block', 'accept', 'accept-unmanageable'], 'type': 'str'},
                'user-agent-detect': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_accessproxyvirtualhost'),
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
