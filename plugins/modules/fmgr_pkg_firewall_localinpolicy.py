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
module: fmgr_pkg_firewall_localinpolicy
short_description: Configure user defined IPv4 local-in policies.
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
    pkg_firewall_localinpolicy:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            action:
                type: str
                description: Action performed on traffic matching the policy
                choices: ['deny', 'accept']
            dstaddr:
                type: raw
                description: (list or str) Destination address object from available options.
            ha_mgmt_intf_only:
                aliases: ['ha-mgmt-intf-only']
                type: str
                description: Enable/disable dedicating the HA management interface only for local-in policy.
                choices: ['disable', 'enable']
            intf:
                type: raw
                description: Incoming interface name from available options.
            policyid:
                type: int
                description: User defined local in policy ID.
                required: true
            schedule:
                type: str
                description: Schedule object from available options.
            service:
                type: raw
                description: (list or str) Service object from available options.
            srcaddr:
                type: raw
                description: (list or str) Source address object from available options.
            status:
                type: str
                description: Enable/disable this local-in policy.
                choices: ['disable', 'enable']
            comments:
                type: str
                description: Comment.
            uuid:
                type: str
                description: Universally Unique Identifier
            dstaddr_negate:
                aliases: ['dstaddr-negate']
                type: str
                description: When enabled dstaddr specifies what the destination address must NOT be.
                choices: ['disable', 'enable']
            service_negate:
                aliases: ['service-negate']
                type: str
                description: When enabled service specifies what the service must NOT be.
                choices: ['disable', 'enable']
            srcaddr_negate:
                aliases: ['srcaddr-negate']
                type: str
                description: When enabled srcaddr specifies what the source address must NOT be.
                choices: ['disable', 'enable']
            virtual_patch:
                aliases: ['virtual-patch']
                type: str
                description: Enable/disable virtual patching.
                choices: ['disable', 'enable']
            internet_service_src:
                aliases: ['internet-service-src']
                type: str
                description: Enable/disable use of Internet Services in source for this local-in policy.
                choices: ['disable', 'enable']
            internet_service_src_custom:
                aliases: ['internet-service-src-custom']
                type: raw
                description: (list) Custom Internet Service source name.
            internet_service_src_custom_group:
                aliases: ['internet-service-src-custom-group']
                type: raw
                description: (list) Custom Internet Service source group name.
            internet_service_src_group:
                aliases: ['internet-service-src-group']
                type: raw
                description: (list) Internet Service source group name.
            internet_service_src_name:
                aliases: ['internet-service-src-name']
                type: raw
                description: (list) Internet Service source name.
            internet_service_src_negate:
                aliases: ['internet-service-src-negate']
                type: str
                description: When enabled internet-service-src specifies what the service must NOT be.
                choices: ['disable', 'enable']
            logtraffic:
                type: str
                description: Enable/disable local-in traffic logging.
                choices: ['disable', 'enable']
            internet_service_src_fortiguard:
                aliases: ['internet-service-src-fortiguard']
                type: raw
                description: (list) FortiGuard Internet Service source name.
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
    - name: Configure user defined IPv4 local-in policies.
      fortinet.fortimanager.fmgr_pkg_firewall_localinpolicy:
        bypass_validation: false
        adom: ansible
        pkg: ansible # package name
        state: present
        pkg_firewall_localinpolicy:
          action: deny # <value in [deny, accept]>
          dstaddr: all
          intf: any
          policyid: 1
          schedule: always
          service: ALL
          srcaddr: all
          status: disable

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the user defined IPv4 local-in policies
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "pkg_firewall_localinpolicy"
          params:
            adom: "ansible"
            pkg: "ansible" # package name
            local_in_policy: "your_value"
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
        '/pm/config/adom/{adom}/pkg/{pkg}/firewall/local-in-policy'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'pkg': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'pkg_firewall_localinpolicy': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'action': {'choices': ['deny', 'accept'], 'type': 'str'},
                'dstaddr': {'type': 'raw'},
                'ha-mgmt-intf-only': {'choices': ['disable', 'enable'], 'type': 'str'},
                'intf': {'type': 'raw'},
                'policyid': {'required': True, 'type': 'int'},
                'schedule': {'type': 'str'},
                'service': {'type': 'raw'},
                'srcaddr': {'type': 'raw'},
                'status': {'choices': ['disable', 'enable'], 'type': 'str'},
                'comments': {'v_range': [['6.2.0', '']], 'type': 'str'},
                'uuid': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'dstaddr-negate': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'service-negate': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'srcaddr-negate': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'virtual-patch': {'v_range': [['7.2.6', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'internet-service-src': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'internet-service-src-custom': {'v_range': [['7.4.3', '']], 'type': 'raw'},
                'internet-service-src-custom-group': {'v_range': [['7.4.3', '']], 'type': 'raw'},
                'internet-service-src-group': {'v_range': [['7.4.3', '']], 'type': 'raw'},
                'internet-service-src-name': {'v_range': [['7.4.3', '']], 'type': 'raw'},
                'internet-service-src-negate': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'logtraffic': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'internet-service-src-fortiguard': {'v_range': [['7.6.4', '']], 'type': 'raw'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'pkg_firewall_localinpolicy'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('full crud', module_arg_spec, urls_list,
                       'policyid', 'data', module, connection)
    fmgr.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
