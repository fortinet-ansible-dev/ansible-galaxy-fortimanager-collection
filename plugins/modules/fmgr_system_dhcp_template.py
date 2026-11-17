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
module: fmgr_system_dhcp_template
short_description: Configure DHCP server templates.
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
  system_dhcp_template:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      auto_configuration:
        aliases: ['auto-configuration']
        type: str
        description: Enable/disable auto configuration.
        choices: ['disable', 'enable']
      conflicted_ip_timeout:
        aliases: ['conflicted-ip-timeout']
        type: int
        description: Time in seconds to wait after a conflicted IP address is removed from the DHCP range before it can be reused.
      ddns_auth:
        aliases: ['ddns-auth']
        type: str
        description: DDNS authentication mode.
        choices: ['disable', 'tsig']
      ddns_key:
        aliases: ['ddns-key']
        type: list
        elements: str
        description: DDNS update key
      ddns_keyname:
        aliases: ['ddns-keyname']
        type: str
        description: DDNS update key name.
      ddns_server_ip:
        aliases: ['ddns-server-ip']
        type: str
        description: DDNS server IP.
      ddns_ttl:
        aliases: ['ddns-ttl']
        type: int
        description: TTL.
      ddns_update:
        aliases: ['ddns-update']
        type: str
        description: Enable/disable DDNS update for DHCP.
        choices: ['disable', 'enable']
      ddns_update_override:
        aliases: ['ddns-update-override']
        type: str
        description: Enable/disable DDNS update override for DHCP.
        choices: ['disable', 'enable']
      ddns_zone:
        aliases: ['ddns-zone']
        type: str
        description: Zone of your domain name
      dns_server1:
        aliases: ['dns-server1']
        type: str
        description: DNS server 1.
      dns_server2:
        aliases: ['dns-server2']
        type: str
        description: DNS server 2.
      dns_server3:
        aliases: ['dns-server3']
        type: str
        description: DNS server 3.
      dns_server4:
        aliases: ['dns-server4']
        type: str
        description: DNS server 4.
      dns_service:
        aliases: ['dns-service']
        type: str
        description: Options for assigning DNS servers to DHCP clients.
        choices: ['default', 'specify', 'local']
      domain:
        type: str
        description: Domain name suffix for the IP addresses that the DHCP server assigns to clients.
      exclude_range:
        aliases: ['exclude-range']
        type: list
        elements: dict
        description: Exclude range.
        suboptions:
          id:
            type: int
            description: ID.
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
          start_ip_index:
            aliases: ['start-ip-index']
            type: int
            description: Start of IP range.
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
      fabric_force_sync:
        aliases: ['fabric-force-sync']
        type: str
        description: Enable/disable forced synchronization of configuration objects from the root FortiGate unit to the downstream devices.
        choices: ['disable', 'enable']
      fabric_object:
        aliases: ['fabric-object']
        type: str
        description: Security Fabric global object setting.
        choices: ['disable', 'enable']
      fabric_object_source:
        aliases: ['fabric-object-source']
        type: str
        description: Fabric object source.
        choices: ['member', 'local', 'root']
      filename:
        type: str
        description: Name of the boot file on the TFTP server.
      forticlient_on_net_status:
        aliases: ['forticlient-on-net-status']
        type: str
        description: Enable/disable FortiClient-On-Net service for this DHCP server.
        choices: ['disable', 'enable']
      ip_range:
        aliases: ['ip-range']
        type: list
        elements: dict
        description: Ip range.
        suboptions:
          id:
            type: int
            description: ID.
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
      ipsec_lease_hold:
        aliases: ['ipsec-lease-hold']
        type: int
        description: DHCP over IPsec leases expire this many seconds after tunnel down
      lease_time:
        aliases: ['lease-time']
        type: int
        description: Lease time in seconds, 0 means unlimited.
      mac_acl_default_action:
        aliases: ['mac-acl-default-action']
        type: str
        description: MAC access control default action
        choices: ['block', 'assign']
      name:
        type: str
        description: DHCP server template name.
        required: true
      next_server:
        aliases: ['next-server']
        type: str
        description: IP address of a server, such as a TFTP server, from which DHCP clients can download a boot file.
      ntp_server1:
        aliases: ['ntp-server1']
        type: str
        description: NTP server 1.
      ntp_server2:
        aliases: ['ntp-server2']
        type: str
        description: NTP server 2.
      ntp_server3:
        aliases: ['ntp-server3']
        type: str
        description: NTP server 3.
      ntp_service:
        aliases: ['ntp-service']
        type: str
        description: Options for assigning Network Time Protocol
        choices: ['default', 'specify', 'local']
      options:
        type: list
        elements: dict
        description: Options.
        suboptions:
          code:
            type: int
            description: DHCP option code.
          id:
            type: int
            description: ID.
          ip:
            type: str
            description: DHCP option IPs.
          type:
            type: str
            description: DHCP option type.
            choices: ['hex', 'string', 'ip', 'fqdn']
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
          value:
            type: str
            description: DHCP option value.
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
      relay_agent:
        aliases: ['relay-agent']
        type: str
        description: Relay agent IP.
      reserve_extra_addresses:
        aliases: ['reserve-extra-addresses']
        type: str
        description: Enable/disable reservation of the extra IP addresses in the subnet.
        choices: ['disable', 'enable']
      reserved_address:
        aliases: ['reserved-address']
        type: list
        elements: dict
        description: Reserved address.
        suboptions:
          action:
            type: str
            description: Options for the DHCP server to configure the client with the reserved MAC address.
            choices: ['assign', 'block', 'reserved']
          circuit_id:
            aliases: ['circuit-id']
            type: str
            description: Option 82 circuit-ID of the client that will get the reserved IP address.
          circuit_id_type:
            aliases: ['circuit-id-type']
            type: str
            description: DHCP option type.
            choices: ['hex', 'string']
          description:
            type: str
            description: Description.
          id:
            type: int
            description: ID.
          ip_index:
            aliases: ['ip-index']
            type: int
            description: Index of IP address to be reserved for the MAC address.
          mac:
            type: str
            description: MAC address of the client that will get the reserved IP address.
          remote_id:
            aliases: ['remote-id']
            type: str
            description: Option 82 remote-ID of the client that will get the reserved IP address.
          remote_id_type:
            aliases: ['remote-id-type']
            type: str
            description: DHCP option type.
            choices: ['hex', 'string']
          type:
            type: str
            description: DHCP reserved-address type.
            choices: ['mac', 'option82']
      server_type:
        aliases: ['server-type']
        type: str
        description: DHCP server can be a normal DHCP server or an IPsec DHCP server.
        choices: ['regular', 'ipsec']
      shared_subnet:
        aliases: ['shared-subnet']
        type: str
        description: Enable/disable shared subnet.
        choices: ['disable', 'enable']
      tftp_server:
        aliases: ['tftp-server']
        type: list
        elements: str
        description: One or more hostnames or IP addresses of the TFTP servers in quotes separated by spaces.
      timezone:
        type: list
        elements: str
        description: Select the time zone to be assigned to DHCP clients.
      timezone_option:
        aliases: ['timezone-option']
        type: str
        description: Options for the DHCP server to set the clients time zone.
        choices: ['disable', 'default', 'specify']
      uuid:
        type: str
        description: Universally Unique Identifier
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
      wifi_ac_service:
        aliases: ['wifi-ac-service']
        type: str
        description: Options for assigning WiFi access controllers to DHCP clients.
        choices: ['specify', 'local']
      wifi_ac1:
        aliases: ['wifi-ac1']
        type: str
        description: WiFi Access Controller 1 IP address
      wifi_ac2:
        aliases: ['wifi-ac2']
        type: str
        description: WiFi Access Controller 2 IP address
      wifi_ac3:
        aliases: ['wifi-ac3']
        type: str
        description: WiFi Access Controller 3 IP address
      wins_server1:
        aliases: ['wins-server1']
        type: str
        description: WINS server 1.
      wins_server2:
        aliases: ['wins-server2']
        type: str
        description: WINS server 2.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure DHCP server templates.
      fortinet.fortimanager.fmgr_system_dhcp_template:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        state: present # <value in [present, absent]>
        system_dhcp_template:
          name: "your value" # Required variable, string
          # auto_configuration: <value in [disable, enable]>
          # conflicted_ip_timeout: <integer>
          # ddns_auth: <value in [disable, tsig]>
          # ddns_key: <list or string>
          # ddns_keyname: <string>
          # ddns_server_ip: <string>
          # ddns_ttl: <integer>
          # ddns_update: <value in [disable, enable]>
          # ddns_update_override: <value in [disable, enable]>
          # ddns_zone: <string>
          # dns_server1: <string>
          # dns_server2: <string>
          # dns_server3: <string>
          # dns_server4: <string>
          # dns_service: <value in [default, specify, local]>
          # domain: <string>
          # exclude_range:
          #   - id: <integer>
          #     ip_count: <integer>
          #     lease_time: <integer>
          #     oui_match: <value in [disable, enable]>
          #     oui_string: <list or string>
          #     start_ip_index: <integer>
          #     uci_match: <value in [disable, enable]>
          #     uci_string: <list or string>
          #     vci_match: <value in [disable, enable]>
          #     vci_string: <list or string>
          #     vendor: <string>
          # fabric_force_sync: <value in [disable, enable]>
          # fabric_object: <value in [disable, enable]>
          # fabric_object_source: <value in [member, local, root]>
          # filename: <string>
          # forticlient_on_net_status: <value in [disable, enable]>
          # ip_range:
          #   - id: <integer>
          #     ip_count: <integer>
          #     lease_time: <integer>
          #     oui_match: <value in [disable, enable]>
          #     oui_string: <list or string>
          #     reserve: <value in [disable, enable]>
          #     uci_match: <value in [disable, enable]>
          #     uci_string: <list or string>
          #     vci_match: <value in [disable, enable]>
          #     vci_string: <list or string>
          #     vendor: <string>
          # ipsec_lease_hold: <integer>
          # lease_time: <integer>
          # mac_acl_default_action: <value in [block, assign]>
          # next_server: <string>
          # ntp_server1: <string>
          # ntp_server2: <string>
          # ntp_server3: <string>
          # ntp_service: <value in [default, specify, local]>
          # options:
          #   - code: <integer>
          #     id: <integer>
          #     ip: <string>
          #     type: <value in [hex, string, ip, ...]>
          #     uci_match: <value in [disable, enable]>
          #     uci_string: <list or string>
          #     value: <string>
          #     vci_match: <value in [disable, enable]>
          #     vci_string: <list or string>
          # relay_agent: <string>
          # reserve_extra_addresses: <value in [disable, enable]>
          # reserved_address:
          #   - action: <value in [assign, block, reserved]>
          #     circuit_id: <string>
          #     circuit_id_type: <value in [hex, string]>
          #     description: <string>
          #     id: <integer>
          #     ip_index: <integer>
          #     mac: <string>
          #     remote_id: <string>
          #     remote_id_type: <value in [hex, string]>
          #     type: <value in [mac, option82]>
          # server_type: <value in [regular, ipsec]>
          # shared_subnet: <value in [disable, enable]>
          # tftp_server: <list or string>
          # timezone: <list or string>
          # timezone_option: <value in [disable, default, specify]>
          # uuid: <string>
          # vci_match: <value in [disable, enable]>
          # vci_string: <list or string>
          # wifi_ac_service: <value in [specify, local]>
          # wifi_ac1: <string>
          # wifi_ac2: <string>
          # wifi_ac3: <string>
          # wins_server1: <string>
          # wins_server2: <string>
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
        '/pm/config/adom/{adom}/obj/system/dhcp/template',
        '/pm/config/global/obj/system/dhcp/template'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'system_dhcp_template': {
            'type': 'dict', 'v_range': [['8.0.1', '']],
            'options': {
                'auto-configuration': {'v_range': [['8.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'conflicted-ip-timeout': {'v_range': [['8.0.1', '']], 'type': 'int'},
                'ddns-auth': {'v_range': [['8.0.1', '']], 'choices': ['disable', 'tsig'], 'type': 'str'},
                'ddns-key': {'v_range': [['8.0.1', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'ddns-keyname': {'v_range': [['8.0.1', '']], 'no_log': True, 'type': 'str'},
                'ddns-server-ip': {'v_range': [['8.0.1', '']], 'type': 'str'},
                'ddns-ttl': {'v_range': [['8.0.1', '']], 'type': 'int'},
                'ddns-update': {'v_range': [['8.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ddns-update-override': {'v_range': [['8.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ddns-zone': {'v_range': [['8.0.1', '']], 'type': 'str'},
                'dns-server1': {'v_range': [['8.0.1', '']], 'type': 'str'},
                'dns-server2': {'v_range': [['8.0.1', '']], 'type': 'str'},
                'dns-server3': {'v_range': [['8.0.1', '']], 'type': 'str'},
                'dns-server4': {'v_range': [['8.0.1', '']], 'type': 'str'},
                'dns-service': {'v_range': [['8.0.1', '']], 'choices': ['default', 'specify', 'local'], 'type': 'str'},
                'domain': {'v_range': [['8.0.1', '']], 'type': 'str'},
                'exclude-range': {
                    'v_range': [['8.0.1', '']],
                    'type': 'list',
                    'options': {
                        'id': {'v_range': [['8.0.1', '']], 'type': 'int'},
                        'ip-count': {'v_range': [['8.0.1', '']], 'type': 'int'},
                        'lease-time': {'v_range': [['8.0.1', '']], 'type': 'int'},
                        'oui-match': {'v_range': [['8.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'oui-string': {'v_range': [['8.0.1', '']], 'type': 'list', 'elements': 'str'},
                        'start-ip-index': {'v_range': [['8.0.1', '']], 'type': 'int'},
                        'uci-match': {'v_range': [['8.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'uci-string': {'v_range': [['8.0.1', '']], 'type': 'list', 'elements': 'str'},
                        'vci-match': {'v_range': [['8.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'vci-string': {'v_range': [['8.0.1', '']], 'type': 'list', 'elements': 'str'},
                        'vendor': {'v_range': [['8.0.1', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'fabric-force-sync': {'v_range': [['8.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fabric-object': {'v_range': [['8.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fabric-object-source': {'v_range': [['8.0.1', '']], 'choices': ['member', 'local', 'root'], 'type': 'str'},
                'filename': {'v_range': [['8.0.1', '']], 'type': 'str'},
                'forticlient-on-net-status': {'v_range': [['8.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ip-range': {
                    'v_range': [['8.0.1', '']],
                    'type': 'list',
                    'options': {
                        'id': {'v_range': [['8.0.1', '']], 'type': 'int'},
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
                    },
                    'elements': 'dict'
                },
                'ipsec-lease-hold': {'v_range': [['8.0.1', '']], 'type': 'int'},
                'lease-time': {'v_range': [['8.0.1', '']], 'type': 'int'},
                'mac-acl-default-action': {'v_range': [['8.0.1', '']], 'choices': ['block', 'assign'], 'type': 'str'},
                'name': {'v_range': [['8.0.1', '']], 'required': True, 'type': 'str'},
                'next-server': {'v_range': [['8.0.1', '']], 'type': 'str'},
                'ntp-server1': {'v_range': [['8.0.1', '']], 'type': 'str'},
                'ntp-server2': {'v_range': [['8.0.1', '']], 'type': 'str'},
                'ntp-server3': {'v_range': [['8.0.1', '']], 'type': 'str'},
                'ntp-service': {'v_range': [['8.0.1', '']], 'choices': ['default', 'specify', 'local'], 'type': 'str'},
                'options': {
                    'v_range': [['8.0.1', '']],
                    'type': 'list',
                    'options': {
                        'code': {'v_range': [['8.0.1', '']], 'type': 'int'},
                        'id': {'v_range': [['8.0.1', '']], 'type': 'int'},
                        'ip': {'v_range': [['8.0.1', '']], 'type': 'str'},
                        'type': {'v_range': [['8.0.1', '']], 'choices': ['hex', 'string', 'ip', 'fqdn'], 'type': 'str'},
                        'uci-match': {'v_range': [['8.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'uci-string': {'v_range': [['8.0.1', '']], 'type': 'list', 'elements': 'str'},
                        'value': {'v_range': [['8.0.1', '']], 'type': 'str'},
                        'vci-match': {'v_range': [['8.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'vci-string': {'v_range': [['8.0.1', '']], 'type': 'list', 'elements': 'str'}
                    },
                    'elements': 'dict'
                },
                'relay-agent': {'v_range': [['8.0.1', '']], 'type': 'str'},
                'reserve-extra-addresses': {'v_range': [['8.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'reserved-address': {
                    'v_range': [['8.0.1', '']],
                    'type': 'list',
                    'options': {
                        'action': {'v_range': [['8.0.1', '']], 'choices': ['assign', 'block', 'reserved'], 'type': 'str'},
                        'circuit-id': {'v_range': [['8.0.1', '']], 'type': 'str'},
                        'circuit-id-type': {'v_range': [['8.0.1', '']], 'choices': ['hex', 'string'], 'type': 'str'},
                        'description': {'v_range': [['8.0.1', '']], 'type': 'str'},
                        'id': {'v_range': [['8.0.1', '']], 'type': 'int'},
                        'ip-index': {'v_range': [['8.0.1', '']], 'type': 'int'},
                        'mac': {'v_range': [['8.0.1', '']], 'type': 'str'},
                        'remote-id': {'v_range': [['8.0.1', '']], 'type': 'str'},
                        'remote-id-type': {'v_range': [['8.0.1', '']], 'choices': ['hex', 'string'], 'type': 'str'},
                        'type': {'v_range': [['8.0.1', '']], 'choices': ['mac', 'option82'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'server-type': {'v_range': [['8.0.1', '']], 'choices': ['regular', 'ipsec'], 'type': 'str'},
                'shared-subnet': {'v_range': [['8.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'tftp-server': {'v_range': [['8.0.1', '']], 'type': 'list', 'elements': 'str'},
                'timezone': {'v_range': [['8.0.1', '']], 'type': 'list', 'elements': 'str'},
                'timezone-option': {'v_range': [['8.0.1', '']], 'choices': ['disable', 'default', 'specify'], 'type': 'str'},
                'uuid': {'v_range': [['8.0.1', '']], 'type': 'str'},
                'vci-match': {'v_range': [['8.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'vci-string': {'v_range': [['8.0.1', '']], 'type': 'list', 'elements': 'str'},
                'wifi-ac-service': {'v_range': [['8.0.1', '']], 'choices': ['specify', 'local'], 'type': 'str'},
                'wifi-ac1': {'v_range': [['8.0.1', '']], 'type': 'str'},
                'wifi-ac2': {'v_range': [['8.0.1', '']], 'type': 'str'},
                'wifi-ac3': {'v_range': [['8.0.1', '']], 'type': 'str'},
                'wins-server1': {'v_range': [['8.0.1', '']], 'type': 'str'},
                'wins-server2': {'v_range': [['8.0.1', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_dhcp_template'),
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
