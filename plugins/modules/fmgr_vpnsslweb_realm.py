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
module: fmgr_vpnsslweb_realm
short_description: Realm.
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
    vpnsslweb_realm:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            login_page:
                aliases: ['login-page']
                type: str
                description: Replacement HTML for SSL-VPN login page.
            max_concurrent_user:
                aliases: ['max-concurrent-user']
                type: int
                description: Maximum concurrent users
            url_path:
                aliases: ['url-path']
                type: str
                description: URL path to access SSL-VPN login page.
            virtual_host:
                aliases: ['virtual-host']
                type: str
                description: Virtual host name for realm.
            nas_ip:
                aliases: ['nas-ip']
                type: str
                description: IP address used as a NAS-IP to communicate with the RADIUS server.
            radius_server:
                aliases: ['radius-server']
                type: str
                description: RADIUS server associated with realm.
            radius_port:
                aliases: ['radius-port']
                type: int
                description: RADIUS service port number
            virtual_host_only:
                aliases: ['virtual-host-only']
                type: str
                description: Enable/disable enforcement of virtual host method for SSL-VPN client access.
                choices: ['disable', 'enable']
            virtual_host_server_cert:
                aliases: ['virtual-host-server-cert']
                type: str
                description: Name of the server certificate to used for this realm.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Realm.
      fortinet.fortimanager.fmgr_vpnsslweb_realm:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        state: present # <value in [present, absent]>
        vpnsslweb_realm:
          # login_page: <string>
          # max_concurrent_user: <integer>
          # url_path: <string>
          # virtual_host: <string>
          # nas_ip: <string>
          # radius_server: <string>
          # radius_port: <integer>
          # virtual_host_only: <value in [disable, enable]>
          # virtual_host_server_cert: <string>
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
        '/pm/config/adom/{adom}/obj/vpn/ssl/web/realm',
        '/pm/config/global/obj/vpn/ssl/web/realm'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'vpnsslweb_realm': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'login-page': {'type': 'str'},
                'max-concurrent-user': {'type': 'int'},
                'url-path': {'type': 'str'},
                'virtual-host': {'type': 'str'},
                'nas-ip': {'v_range': [['6.4.0', '']], 'type': 'str'},
                'radius-server': {'v_range': [['6.4.0', '']], 'type': 'str'},
                'radius-port': {'v_range': [['6.4.2', '']], 'type': 'int'},
                'virtual-host-only': {'v_range': [['6.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'virtual-host-server-cert': {'v_range': [['7.0.2', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'vpnsslweb_realm'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('full crud', module_arg_spec, urls_list,
                       None, 'data', module, connection)
    fmgr.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
