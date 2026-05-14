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
module: fmgr_webfilter_urlfilter
short_description: Configure URL filter lists.
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
    webfilter_urlfilter:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            comment:
                type: str
                description: Optional comments.
            entries:
                type: list
                elements: dict
                description: Entries.
                suboptions:
                    action:
                        type: str
                        description: Action to take for URL filter matches.
                        choices: ['exempt', 'block', 'allow', 'monitor', 'pass']
                    dns_address_family:
                        aliases: ['dns-address-family']
                        type: str
                        description: Resolve IPv4 address, IPv6 address, or both from DNS server.
                        choices: ['ipv4', 'ipv6', 'both']
                    exempt:
                        type: list
                        elements: str
                        description: If action is set to exempt, select the security profile operations that exempt URLs skip.
                        choices: ['av', 'web-content', 'activex-java-cookie', 'dlp', 'fortiguard',
                                  'all', 'filepattern', 'pass', 'range-block', 'antiphish']
                    id:
                        type: int
                        description: Id.
                    referrer_host:
                        aliases: ['referrer-host']
                        type: str
                        description: Referrer host name.
                    status:
                        type: str
                        description: Enable/disable this URL filter.
                        choices: ['disable', 'enable']
                    type:
                        type: str
                        description: Filter type
                        choices: ['simple', 'regex', 'wildcard']
                    url:
                        type: str
                        description: URL to be filtered.
                    web_proxy_profile:
                        aliases: ['web-proxy-profile']
                        type: str
                        description: Web proxy profile.
                    antiphish_action:
                        aliases: ['antiphish-action']
                        type: str
                        description: Action to take for AntiPhishing matches.
                        choices: ['block', 'log']
                    comment:
                        type: str
                        description: Comment.
            id:
                type: int
                description: ID.
                required: true
            ip_addr_block:
                aliases: ['ip-addr-block']
                type: str
                description: Enable/disable blocking URLs when the hostname appears as an IP address.
                choices: ['disable', 'enable']
            name:
                type: str
                description: Name of URL filter list.
            one_arm_ips_urlfilter:
                aliases: ['one-arm-ips-urlfilter']
                type: str
                description: Enable/disable DNS resolver for one-arm IPS URL filter operation.
                choices: ['disable', 'enable']
            ip4_mapped_ip6:
                aliases: ['ip4-mapped-ip6']
                type: str
                description: Enable/disable matching of IPv4 mapped IPv6 URLs.
                choices: ['disable', 'enable']
            include_subdomains:
                aliases: ['include-subdomains']
                type: str
                description: Enable/disable matching subdomains.
                choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure URL filter lists.
      fortinet.fortimanager.fmgr_webfilter_urlfilter:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        state: present # <value in [present, absent]>
        webfilter_urlfilter:
          id: 0 # Required variable, integer
          # comment: <string>
          # entries:
          #   - action: <value in [exempt, block, allow, ...]>
          #     dns_address_family: <value in [ipv4, ipv6, both]>
          #     exempt: ["av", "web-content", "activex-java-cookie", "dlp", "fortiguard", "all",
          #              "filepattern", "pass", "range-block", "antiphish"]
          #     id: <integer>
          #     referrer_host: <string>
          #     status: <value in [disable, enable]>
          #     type: <value in [simple, regex, wildcard]>
          #     url: <string>
          #     web_proxy_profile: <string>
          #     antiphish_action: <value in [block, log]>
          #     comment: <string>
          # ip_addr_block: <value in [disable, enable]>
          # name: <string>
          # one_arm_ips_urlfilter: <value in [disable, enable]>
          # ip4_mapped_ip6: <value in [disable, enable]>
          # include_subdomains: <value in [disable, enable]>
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
        '/pm/config/adom/{adom}/obj/webfilter/urlfilter',
        '/pm/config/global/obj/webfilter/urlfilter'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'webfilter_urlfilter': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'comment': {'type': 'str'},
                'entries': {
                    'type': 'list',
                    'options': {
                        'action': {'choices': ['exempt', 'block', 'allow', 'monitor', 'pass'], 'type': 'str'},
                        'dns-address-family': {'choices': ['ipv4', 'ipv6', 'both'], 'type': 'str'},
                        'exempt': {
                            'type': 'list',
                            'choices': [
                                'av', 'web-content', 'activex-java-cookie', 'dlp', 'fortiguard', 'all', 'filepattern', 'pass', 'range-block',
                                'antiphish'
                            ],
                            'elements': 'str'
                        },
                        'id': {'type': 'int'},
                        'referrer-host': {'type': 'str'},
                        'status': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'type': {'choices': ['simple', 'regex', 'wildcard'], 'type': 'str'},
                        'url': {'type': 'str'},
                        'web-proxy-profile': {'type': 'str'},
                        'antiphish-action': {'v_range': [['6.4.0', '']], 'choices': ['block', 'log'], 'type': 'str'},
                        'comment': {'v_range': [['7.6.4', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'id': {'required': True, 'type': 'int'},
                'ip-addr-block': {'choices': ['disable', 'enable'], 'type': 'str'},
                'name': {'type': 'str'},
                'one-arm-ips-urlfilter': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ip4-mapped-ip6': {'v_range': [['7.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'include-subdomains': {'v_range': [['7.4.8', '7.4.10'], ['7.6.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'webfilter_urlfilter'),
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
