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
module: fmgr_devprof_system_dns
short_description: Configure DNS.
version_added: "1.0.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.partial_crud
options:
    adom:
        description: The parameter (adom) in requested url.
        type: str
        required: true
    devprof:
        description: The parameter (devprof) in requested url.
        type: str
        required: true
    devprof_system_dns:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            cache_notfound_responses:
                aliases: ['cache-notfound-responses']
                type: str
                description: Enable/disable response from the DNS server when a record is not in cache.
                choices: ['disable', 'enable']
            dns_cache_limit:
                aliases: ['dns-cache-limit']
                type: int
                description: Maximum number of records in the DNS cache.
            dns_cache_ttl:
                aliases: ['dns-cache-ttl']
                type: int
                description: Duration in seconds that the DNS cache retains information.
            domain:
                type: raw
                description: (list or str) Domain name suffix for the IP addresses of the DNS server.
            ip6_primary:
                aliases: ['ip6-primary']
                type: str
                description: Primary DNS server IPv6 address.
            ip6_secondary:
                aliases: ['ip6-secondary']
                type: str
                description: Secondary DNS server IPv6 address.
            primary:
                type: str
                description: Primary DNS server IP address.
            secondary:
                type: str
                description: Secondary DNS server IP address.
            dns_over_tls:
                aliases: ['dns-over-tls']
                type: str
                description: Enable/disable/enforce DNS over TLS.
                choices: ['disable', 'enable', 'enforce']
            retry:
                type: int
                description: Number of times to retry
            server_hostname:
                aliases: ['server-hostname']
                type: raw
                description: (list) DNS server host name list.
            ssl_certificate:
                aliases: ['ssl-certificate']
                type: str
                description: Name of local certificate for SSL connections.
            timeout:
                type: int
                description: DNS query timeout interval in seconds
            interface:
                type: str
                description: Specify outgoing interface to reach server.
            interface_select_method:
                aliases: ['interface-select-method']
                type: str
                description: Specify how to select outgoing interface to reach server.
                choices: ['auto', 'sdwan', 'specify']
            alt_primary:
                aliases: ['alt-primary']
                type: str
                description: Alternate primary DNS server.
            alt_secondary:
                aliases: ['alt-secondary']
                type: str
                description: Alternate secondary DNS server.
            fqdn_cache_ttl:
                aliases: ['fqdn-cache-ttl']
                type: int
                description: FQDN cache time to live in seconds
            fqdn_max_refresh:
                aliases: ['fqdn-max-refresh']
                type: int
                description: FQDN cache maximum refresh time in seconds
            fqdn_min_refresh:
                aliases: ['fqdn-min-refresh']
                type: int
                description: FQDN cache minimum refresh time in seconds
            log:
                type: str
                description: Local DNS log setting.
                choices: ['disable', 'error', 'all']
            protocol:
                type: list
                elements: str
                description: DNS transport protocols.
                choices: ['cleartext', 'dot', 'doh']
            server_select_method:
                aliases: ['server-select-method']
                type: str
                description: Specify how configured servers are prioritized.
                choices: ['least-rtt', 'failover']
            source_ip:
                aliases: ['source-ip']
                type: str
                description: IP address used by the DNS server as its source IP.
            vrf_select:
                aliases: ['vrf-select']
                type: int
                description: VRF ID used for connection to server.
            source_ip_interface:
                aliases: ['source-ip-interface']
                type: raw
                description: (list) IP address of the specified interface as the source IP address.
            hostname_ttl:
                aliases: ['hostname-ttl']
                type: int
                description: TTL of hostname table entries
            hostname_limit:
                aliases: ['hostname-limit']
                type: int
                description: Limit of the number of hostname table entries
            root_servers:
                aliases: ['root-servers']
                type: str
                description: Configure up to two preferred servers that serve the DNS root zone
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure DNS.
      fortinet.fortimanager.fmgr_devprof_system_dns:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        devprof: <your own value>
        devprof_system_dns:
          # cache_notfound_responses: <value in [disable, enable]>
          # dns_cache_limit: <integer>
          # dns_cache_ttl: <integer>
          # domain: <list or string>
          # ip6_primary: <string>
          # ip6_secondary: <string>
          # primary: <string>
          # secondary: <string>
          # dns_over_tls: <value in [disable, enable, enforce]>
          # retry: <integer>
          # server_hostname: <list or string>
          # ssl_certificate: <string>
          # timeout: <integer>
          # interface: <string>
          # interface_select_method: <value in [auto, sdwan, specify]>
          # alt_primary: <string>
          # alt_secondary: <string>
          # fqdn_cache_ttl: <integer>
          # fqdn_max_refresh: <integer>
          # fqdn_min_refresh: <integer>
          # log: <value in [disable, error, all]>
          # protocol: ["cleartext", "dot", "doh"]
          # server_select_method: <value in [least-rtt, failover]>
          # source_ip: <string>
          # vrf_select: <integer>
          # source_ip_interface: <list or string>
          # hostname_ttl: <integer>
          # hostname_limit: <integer>
          # root_servers: <string>
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
        '/pm/config/adom/{adom}/devprof/{devprof}/system/dns'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'devprof': {'required': True, 'type': 'str'},
        'devprof_system_dns': {
            'type': 'dict', 'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['7.6.5', '']],
            'options': {
                'cache-notfound-responses': {
                    'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['7.6.5', '']],
                    'choices': ['disable', 'enable'],
                    'type': 'str'
                },
                'dns-cache-limit': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['7.6.5', '']], 'type': 'int'},
                'dns-cache-ttl': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['7.6.5', '']], 'type': 'int'},
                'domain': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['7.6.5', '']], 'type': 'raw'},
                'ip6-primary': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['7.6.5', '']], 'type': 'str'},
                'ip6-secondary': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['7.6.5', '']], 'type': 'str'},
                'primary': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['7.6.5', '']], 'type': 'str'},
                'secondary': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['7.6.5', '']], 'type': 'str'},
                'dns-over-tls': {
                    'v_range': [['6.2.0', '6.2.5'], ['6.2.7', '6.4.1'], ['7.6.5', '']],
                    'choices': ['disable', 'enable', 'enforce'],
                    'type': 'str'
                },
                'retry': {'v_range': [['6.2.0', '6.2.5'], ['6.2.7', '6.4.1'], ['7.6.5', '']], 'type': 'int'},
                'server-hostname': {'v_range': [['6.2.1', '6.2.5'], ['6.2.7', '6.4.1'], ['7.6.5', '']], 'type': 'raw'},
                'ssl-certificate': {'v_range': [['6.2.0', '6.2.5'], ['6.2.7', '6.4.1'], ['7.6.5', '']], 'type': 'str'},
                'timeout': {'v_range': [['6.2.0', '6.2.5'], ['6.2.7', '6.4.1'], ['7.6.5', '']], 'type': 'int'},
                'interface': {'v_range': [['6.2.5', '6.2.5'], ['6.2.7', '6.2.13'], ['6.4.1', '6.4.1'], ['7.6.5', '']], 'type': 'str'},
                'interface-select-method': {
                    'v_range': [['6.2.5', '6.2.5'], ['6.2.7', '6.2.13'], ['6.4.1', '6.4.1'], ['7.6.5', '']],
                    'choices': ['auto', 'sdwan', 'specify'],
                    'type': 'str'
                },
                'alt-primary': {'v_range': [['7.6.5', '']], 'type': 'str'},
                'alt-secondary': {'v_range': [['7.6.5', '']], 'type': 'str'},
                'fqdn-cache-ttl': {'v_range': [['7.6.5', '']], 'type': 'int'},
                'fqdn-max-refresh': {'v_range': [['7.6.5', '']], 'type': 'int'},
                'fqdn-min-refresh': {'v_range': [['7.6.5', '']], 'type': 'int'},
                'log': {'v_range': [['7.6.5', '']], 'choices': ['disable', 'error', 'all'], 'type': 'str'},
                'protocol': {'v_range': [['7.6.5', '']], 'type': 'list', 'choices': ['cleartext', 'dot', 'doh'], 'elements': 'str'},
                'server-select-method': {'v_range': [['7.6.5', '']], 'choices': ['least-rtt', 'failover'], 'type': 'str'},
                'source-ip': {'v_range': [['7.6.5', '']], 'type': 'str'},
                'vrf-select': {'v_range': [['7.6.5', '']], 'type': 'int'},
                'source-ip-interface': {'v_range': [['7.6.5', '']], 'type': 'raw'},
                'hostname-ttl': {'v_range': [['7.6.5', '']], 'type': 'int'},
                'hostname-limit': {'v_range': [['7.6.5', '']], 'type': 'int'},
                'root-servers': {'v_range': [['7.6.5', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'devprof_system_dns'),
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
