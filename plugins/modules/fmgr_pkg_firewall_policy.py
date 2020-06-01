#!/usr/bin/python
from __future__ import absolute_import, division, print_function
# Copyright 2019-2020 Fortinet, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

__metaclass__ = type

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'metadata_version': '1.1'}

DOCUMENTATION = '''
---
module: fmgr_pkg_firewall_policy
short_description: Configure IPv4 policies.
description:
    - This module is able to configure a FortiManager device by allowing the
      user to [ add get set update ] the following apis.
    - /pm/config/adom/{adom}/pkg/{pkg}/firewall/policy
    - Examples include all parameters and values need to be adjusted to data sources before usage.

version_added: "2.10"
author:
    - Frank Shen (@fshen01)
    - Link Zheng (@zhengl)
notes:
    - There are only three top-level parameters where 'method' is always required
      while other two 'params' and 'url_params' can be optional
    - Due to the complexity of fortimanager api schema, the validation is done
      out of Ansible native parameter validation procedure.
    - The syntax of OPTIONS doen not comply with the standard Ansible argument
      specification, but with the structure of fortimanager API schema, we need
      a trivial transformation when we are filling the ansible playbook
options:
    loose_validation:
        description:
          - Do parameter validation in a loose way
        type: bool
        required: false
    workspace_locking_adom:
        description:
          - the adom name to lock in case FortiManager running in workspace mode
          - it can be global or any other custom adom names
        required: false
        type: str
    workspace_locking_timeout:
        description:
          - the maximum time in seconds to wait for other user to release the workspace lock
        required: false
        type: int
        default: 300
    method:
        description:
          - The method in request
        required: true
        type: str
        choices:
          - add
          - get
          - set
          - update
    params:
        description:
          - The parameters for each method
          - See full parameters list in https://ansible-galaxy-fortimanager-docs.readthedocs.io/en/latest
        type: list
        required: false
    url_params:
        description:
          - The parameters for each API request URL
          - Also see full URL parameters in https://ansible-galaxy-fortimanager-docs.readthedocs.io/en/latest
        required: false
        type: dict

'''

EXAMPLES = '''
 - hosts: fortimanager-inventory
   collections:
     - fortinet.fortimanager
   connection: httpapi
   vars:
      ansible_httpapi_use_ssl: True
      ansible_httpapi_validate_certs: False
      ansible_httpapi_port: 443
   tasks:

    - name: REQUESTING /PM/CONFIG/PKG/{PKG}/FIREWALL/POLICY
      fmgr_pkg_firewall_policy:
         loose_validation: False
         workspace_locking_adom: <value in [global, custom adom]>
         workspace_locking_timeout: 300
         method: <value in [add, set, update]>
         url_params:
            adom: <value in [none, global, custom dom]>
            pkg: <value of string>
         params:
            -
               data:
                 -
                     action: <value in [deny, accept, ipsec, ...]>
                     app-category: <value of string>
                     application:
                       - <value of integer>
                     application-list: <value of string>
                     auth-cert: <value of string>
                     auth-path: <value in [disable, enable]>
                     auth-redirect-addr: <value of string>
                     auto-asic-offload: <value in [disable, enable]>
                     av-profile: <value of string>
                     block-notification: <value in [disable, enable]>
                     captive-portal-exempt: <value in [disable, enable]>
                     capture-packet: <value in [disable, enable]>
                     comments: <value of string>
                     custom-log-fields: <value of string>
                     delay-tcp-npu-session: <value in [disable, enable]>
                     devices: <value of string>
                     diffserv-forward: <value in [disable, enable]>
                     diffserv-reverse: <value in [disable, enable]>
                     diffservcode-forward: <value of string>
                     diffservcode-rev: <value of string>
                     disclaimer: <value in [disable, enable]>
                     dlp-sensor: <value of string>
                     dnsfilter-profile: <value of string>
                     dscp-match: <value in [disable, enable]>
                     dscp-negate: <value in [disable, enable]>
                     dscp-value: <value of string>
                     dsri: <value in [disable, enable]>
                     dstaddr: <value of string>
                     dstaddr-negate: <value in [disable, enable]>
                     dstintf: <value of string>
                     firewall-session-dirty: <value in [check-all, check-new]>
                     fixedport: <value in [disable, enable]>
                     fsso: <value in [disable, enable]>
                     fsso-agent-for-ntlm: <value of string>
                     global-label: <value of string>
                     groups: <value of string>
                     gtp-profile: <value of string>
                     icap-profile: <value of string>
                     identity-based-route: <value of string>
                     inbound: <value in [disable, enable]>
                     internet-service: <value in [disable, enable]>
                     internet-service-custom: <value of string>
                     internet-service-id: <value of string>
                     internet-service-negate: <value in [disable, enable]>
                     ippool: <value in [disable, enable]>
                     ips-sensor: <value of string>
                     label: <value of string>
                     learning-mode: <value in [disable, enable]>
                     logtraffic: <value in [disable, enable, all, ...]>
                     logtraffic-start: <value in [disable, enable]>
                     match-vip: <value in [disable, enable]>
                     mms-profile: <value of string>
                     name: <value of string>
                     nat: <value in [disable, enable]>
                     natinbound: <value in [disable, enable]>
                     natip: <value of string>
                     natoutbound: <value in [disable, enable]>
                     ntlm: <value in [disable, enable]>
                     ntlm-enabled-browsers:
                       - <value of string>
                     ntlm-guest: <value in [disable, enable]>
                     outbound: <value in [disable, enable]>
                     per-ip-shaper: <value of string>
                     permit-any-host: <value in [disable, enable]>
                     permit-stun-host: <value in [disable, enable]>
                     policyid: <value of integer>
                     poolname: <value of string>
                     profile-group: <value of string>
                     profile-protocol-options: <value of string>
                     profile-type: <value in [single, group]>
                     radius-mac-auth-bypass: <value in [disable, enable]>
                     redirect-url: <value of string>
                     replacemsg-override-group: <value of string>
                     rsso: <value in [disable, enable]>
                     rtp-addr: <value of string>
                     rtp-nat: <value in [disable, enable]>
                     scan-botnet-connections: <value in [disable, block, monitor]>
                     schedule: <value of string>
                     schedule-timeout: <value in [disable, enable]>
                     send-deny-packet: <value in [disable, enable]>
                     service: <value of string>
                     service-negate: <value in [disable, enable]>
                     session-ttl: <value of integer>
                     spamfilter-profile: <value of string>
                     srcaddr: <value of string>
                     srcaddr-negate: <value in [disable, enable]>
                     srcintf: <value of string>
                     ssl-mirror: <value in [disable, enable]>
                     ssl-mirror-intf: <value of string>
                     ssl-ssh-profile: <value of string>
                     status: <value in [disable, enable]>
                     tags: <value of string>
                     tcp-mss-receiver: <value of integer>
                     tcp-mss-sender: <value of integer>
                     tcp-session-without-syn: <value in [all, data-only, disable]>
                     timeout-send-rst: <value in [disable, enable]>
                     traffic-shaper: <value of string>
                     traffic-shaper-reverse: <value of string>
                     url-category: <value of string>
                     users: <value of string>
                     utm-status: <value in [disable, enable]>
                     uuid: <value of string>
                     vlan-cos-fwd: <value of integer>
                     vlan-cos-rev: <value of integer>
                     voip-profile: <value of string>
                     vpn_dst_node:
                       -
                           host: <value of string>
                           seq: <value of integer>
                           subnet: <value of string>
                     vpn_src_node:
                       -
                           host: <value of string>
                           seq: <value of integer>
                           subnet: <value of string>
                     vpntunnel: <value of string>
                     waf-profile: <value of string>
                     wanopt: <value in [disable, enable]>
                     wanopt-detection: <value in [active, passive, off]>
                     wanopt-passive-opt: <value in [default, transparent, non-transparent]>
                     wanopt-peer: <value of string>
                     wanopt-profile: <value of string>
                     wccp: <value in [disable, enable]>
                     webcache: <value in [disable, enable]>
                     webcache-https: <value in [disable, ssl-server, any, ...]>
                     webfilter-profile: <value of string>
                     wsso: <value in [disable, enable]>

    - name: REQUESTING /PM/CONFIG/PKG/{PKG}/FIREWALL/POLICY
      fmgr_pkg_firewall_policy:
         loose_validation: False
         workspace_locking_adom: <value in [global, custom adom]>
         workspace_locking_timeout: 300
         method: <value in [get]>
         url_params:
            adom: <value in [none, global, custom dom]>
            pkg: <value of string>
         params:
            -
               attr: <value of string>
               fields:
                 -
                    - <value in [action, app-category, application, ...]>
               filter:
                 - <value of string>
               get used: <value of integer>
               loadsub: <value of integer>
               option: <value in [count, object member, datasrc, ...]>
               range:
                 - <value of integer>
               sortings:
                 -
                     varidic.attr_name: <value in [1, -1]>

'''

RETURN = '''
url:
    description: The full url requested
    returned: always
    type: str
    sample: /sys/login/user
status:
    description: The status of api request
    returned: always
    type: dict
data:
    description: The payload returned in the request
    type: dict
    returned: always

'''
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortimanager.plugins.module_utils.common import FAIL_SOCKET_MSG
from ansible_collections.fortinet.fortimanager.plugins.module_utils.common import DEFAULT_RESULT_OBJ
from ansible_collections.fortinet.fortimanager.plugins.module_utils.common import FMGRCommon
from ansible_collections.fortinet.fortimanager.plugins.module_utils.common import FMGBaseException
from ansible_collections.fortinet.fortimanager.plugins.module_utils.fortimanager import FortiManagerHandler


def main():
    jrpc_urls = [
        '/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy'
    ]

    url_schema = [
        {
            'name': 'adom',
            'type': 'string'
        },
        {
            'name': 'pkg',
            'type': 'string'
        }
    ]

    body_schema = {
        'schema_objects': {
            'object0': [
                {
                    'name': 'data',
                    'api_tag': 0,
                    'type': 'array',
                    'items': {
                        'action': {
                            'type': 'string',
                            'enum': [
                                'deny',
                                'accept',
                                'ipsec',
                                'ssl-vpn'
                            ]
                        },
                        'app-category': {
                            'type': 'string'
                        },
                        'application': {
                            'type': 'array',
                            'items': {
                                'type': 'integer'
                            }
                        },
                        'application-list': {
                            'type': 'string'
                        },
                        'auth-cert': {
                            'type': 'string'
                        },
                        'auth-path': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'auth-redirect-addr': {
                            'type': 'string'
                        },
                        'auto-asic-offload': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'av-profile': {
                            'type': 'string'
                        },
                        'block-notification': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'captive-portal-exempt': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'capture-packet': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'comments': {
                            'type': 'string'
                        },
                        'custom-log-fields': {
                            'type': 'string'
                        },
                        'delay-tcp-npu-session': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'devices': {
                            'type': 'string'
                        },
                        'diffserv-forward': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'diffserv-reverse': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'diffservcode-forward': {
                            'type': 'string'
                        },
                        'diffservcode-rev': {
                            'type': 'string'
                        },
                        'disclaimer': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'dlp-sensor': {
                            'type': 'string'
                        },
                        'dnsfilter-profile': {
                            'type': 'string'
                        },
                        'dscp-match': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'dscp-negate': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'dscp-value': {
                            'type': 'string'
                        },
                        'dsri': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'dstaddr': {
                            'type': 'string'
                        },
                        'dstaddr-negate': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'dstintf': {
                            'type': 'string'
                        },
                        'firewall-session-dirty': {
                            'type': 'string',
                            'enum': [
                                'check-all',
                                'check-new'
                            ]
                        },
                        'fixedport': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'fsso': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'fsso-agent-for-ntlm': {
                            'type': 'string'
                        },
                        'global-label': {
                            'type': 'string'
                        },
                        'groups': {
                            'type': 'string'
                        },
                        'gtp-profile': {
                            'type': 'string'
                        },
                        'icap-profile': {
                            'type': 'string'
                        },
                        'identity-based-route': {
                            'type': 'string'
                        },
                        'inbound': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'internet-service': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'internet-service-custom': {
                            'type': 'string'
                        },
                        'internet-service-id': {
                            'type': 'string'
                        },
                        'internet-service-negate': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'ippool': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'ips-sensor': {
                            'type': 'string'
                        },
                        'label': {
                            'type': 'string'
                        },
                        'learning-mode': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'logtraffic': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable',
                                'all',
                                'utm'
                            ]
                        },
                        'logtraffic-start': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'match-vip': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'mms-profile': {
                            'type': 'string'
                        },
                        'name': {
                            'type': 'string'
                        },
                        'nat': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'natinbound': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'natip': {
                            'type': 'string'
                        },
                        'natoutbound': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'ntlm': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'ntlm-enabled-browsers': {
                            'type': 'array',
                            'items': {
                                'type': 'string'
                            }
                        },
                        'ntlm-guest': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'outbound': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'per-ip-shaper': {
                            'type': 'string'
                        },
                        'permit-any-host': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'permit-stun-host': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'policyid': {
                            'type': 'integer'
                        },
                        'poolname': {
                            'type': 'string'
                        },
                        'profile-group': {
                            'type': 'string'
                        },
                        'profile-protocol-options': {
                            'type': 'string'
                        },
                        'profile-type': {
                            'type': 'string',
                            'enum': [
                                'single',
                                'group'
                            ]
                        },
                        'radius-mac-auth-bypass': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'redirect-url': {
                            'type': 'string'
                        },
                        'replacemsg-override-group': {
                            'type': 'string'
                        },
                        'rsso': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'rtp-addr': {
                            'type': 'string'
                        },
                        'rtp-nat': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'scan-botnet-connections': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'block',
                                'monitor'
                            ]
                        },
                        'schedule': {
                            'type': 'string'
                        },
                        'schedule-timeout': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'send-deny-packet': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'service': {
                            'type': 'string'
                        },
                        'service-negate': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'session-ttl': {
                            'type': 'integer'
                        },
                        'spamfilter-profile': {
                            'type': 'string'
                        },
                        'srcaddr': {
                            'type': 'string'
                        },
                        'srcaddr-negate': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'srcintf': {
                            'type': 'string'
                        },
                        'ssl-mirror': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'ssl-mirror-intf': {
                            'type': 'string'
                        },
                        'ssl-ssh-profile': {
                            'type': 'string'
                        },
                        'status': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'tags': {
                            'type': 'string'
                        },
                        'tcp-mss-receiver': {
                            'type': 'integer'
                        },
                        'tcp-mss-sender': {
                            'type': 'integer'
                        },
                        'tcp-session-without-syn': {
                            'type': 'string',
                            'enum': [
                                'all',
                                'data-only',
                                'disable'
                            ]
                        },
                        'timeout-send-rst': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'traffic-shaper': {
                            'type': 'string'
                        },
                        'traffic-shaper-reverse': {
                            'type': 'string'
                        },
                        'url-category': {
                            'type': 'string'
                        },
                        'users': {
                            'type': 'string'
                        },
                        'utm-status': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'uuid': {
                            'type': 'string'
                        },
                        'vlan-cos-fwd': {
                            'type': 'integer'
                        },
                        'vlan-cos-rev': {
                            'type': 'integer'
                        },
                        'voip-profile': {
                            'type': 'string'
                        },
                        'vpn_dst_node': {
                            'type': 'array',
                            'items': {
                                'host': {
                                    'type': 'string'
                                },
                                'seq': {
                                    'type': 'integer'
                                },
                                'subnet': {
                                    'type': 'string'
                                }
                            }
                        },
                        'vpn_src_node': {
                            'type': 'array',
                            'items': {
                                'host': {
                                    'type': 'string'
                                },
                                'seq': {
                                    'type': 'integer'
                                },
                                'subnet': {
                                    'type': 'string'
                                }
                            }
                        },
                        'vpntunnel': {
                            'type': 'string'
                        },
                        'waf-profile': {
                            'type': 'string'
                        },
                        'wanopt': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'wanopt-detection': {
                            'type': 'string',
                            'enum': [
                                'active',
                                'passive',
                                'off'
                            ]
                        },
                        'wanopt-passive-opt': {
                            'type': 'string',
                            'enum': [
                                'default',
                                'transparent',
                                'non-transparent'
                            ]
                        },
                        'wanopt-peer': {
                            'type': 'string'
                        },
                        'wanopt-profile': {
                            'type': 'string'
                        },
                        'wccp': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'webcache': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'webcache-https': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'ssl-server',
                                'any',
                                'enable'
                            ]
                        },
                        'webfilter-profile': {
                            'type': 'string'
                        },
                        'wsso': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        }
                    }
                },
                {
                    'type': 'string',
                    'name': 'url',
                    'api_tag': 0
                }
            ],
            'object1': [
                {
                    'type': 'string',
                    'name': 'attr',
                    'api_tag': 0
                },
                {
                    'name': 'fields',
                    'api_tag': 0,
                    'type': 'array',
                    'items': {
                        'type': 'array',
                        'items': {
                            'type': 'string',
                            'enum': [
                                'action',
                                'app-category',
                                'application',
                                'application-list',
                                'auth-cert',
                                'auth-path',
                                'auth-redirect-addr',
                                'auto-asic-offload',
                                'av-profile',
                                'block-notification',
                                'captive-portal-exempt',
                                'capture-packet',
                                'custom-log-fields',
                                'delay-tcp-npu-session',
                                'devices',
                                'diffserv-forward',
                                'diffserv-reverse',
                                'diffservcode-forward',
                                'diffservcode-rev',
                                'disclaimer',
                                'dlp-sensor',
                                'dnsfilter-profile',
                                'dscp-match',
                                'dscp-negate',
                                'dscp-value',
                                'dsri',
                                'dstaddr',
                                'dstaddr-negate',
                                'dstintf',
                                'firewall-session-dirty',
                                'fixedport',
                                'fsso',
                                'fsso-agent-for-ntlm',
                                'global-label',
                                'groups',
                                'gtp-profile',
                                'icap-profile',
                                'identity-based-route',
                                'inbound',
                                'internet-service',
                                'internet-service-custom',
                                'internet-service-id',
                                'internet-service-negate',
                                'ippool',
                                'ips-sensor',
                                'label',
                                'learning-mode',
                                'logtraffic',
                                'logtraffic-start',
                                'match-vip',
                                'mms-profile',
                                'name',
                                'nat',
                                'natinbound',
                                'natip',
                                'natoutbound',
                                'ntlm',
                                'ntlm-enabled-browsers',
                                'ntlm-guest',
                                'outbound',
                                'per-ip-shaper',
                                'permit-any-host',
                                'permit-stun-host',
                                'policyid',
                                'poolname',
                                'profile-group',
                                'profile-protocol-options',
                                'profile-type',
                                'radius-mac-auth-bypass',
                                'redirect-url',
                                'replacemsg-override-group',
                                'rsso',
                                'rtp-addr',
                                'rtp-nat',
                                'scan-botnet-connections',
                                'schedule',
                                'schedule-timeout',
                                'send-deny-packet',
                                'service',
                                'service-negate',
                                'session-ttl',
                                'spamfilter-profile',
                                'srcaddr',
                                'srcaddr-negate',
                                'srcintf',
                                'ssl-mirror',
                                'ssl-mirror-intf',
                                'ssl-ssh-profile',
                                'status',
                                'tags',
                                'tcp-mss-receiver',
                                'tcp-mss-sender',
                                'tcp-session-without-syn',
                                'timeout-send-rst',
                                'traffic-shaper',
                                'traffic-shaper-reverse',
                                'url-category',
                                'users',
                                'utm-status',
                                'uuid',
                                'vlan-cos-fwd',
                                'vlan-cos-rev',
                                'voip-profile',
                                'vpntunnel',
                                'waf-profile',
                                'wanopt',
                                'wanopt-detection',
                                'wanopt-passive-opt',
                                'wanopt-peer',
                                'wanopt-profile',
                                'wccp',
                                'webcache',
                                'webcache-https',
                                'webfilter-profile',
                                'wsso'
                            ]
                        }
                    }
                },
                {
                    'name': 'filter',
                    'type': 'dict',
                    'dict': {
                        'type': 'array',
                        'items': {
                            'type': 'string',
                            'example': [
                                '<attr>',
                                '==',
                                'test'
                            ]
                        }
                    },
                    'api_tag': 0
                },
                {
                    'type': 'integer',
                    'name': 'get used',
                    'api_tag': 0
                },
                {
                    'type': 'integer',
                    'name': 'loadsub',
                    'api_tag': 0
                },
                {
                    'name': 'option',
                    'type': 'dict',
                    'dict': {
                        'type': 'string',
                        'enum': [
                            'count',
                            'object member',
                            'datasrc',
                            'get reserved',
                            'syntax'
                        ]
                    },
                    'api_tag': 0
                },
                {
                    'name': 'range',
                    'type': 'dict',
                    'dict': {
                        'type': 'array',
                        'items': {
                            'type': 'integer',
                            'example': [
                                2,
                                5
                            ]
                        }
                    },
                    'api_tag': 0
                },
                {
                    'name': 'sortings',
                    'type': 'dict',
                    'dict': {
                        'type': 'array',
                        'items': {
                            '{attr_name}': {
                                'type': 'integer',
                                'enum': [
                                    1,
                                    -1
                                ]
                            }
                        }
                    },
                    'api_tag': 0
                },
                {
                    'type': 'string',
                    'name': 'url',
                    'api_tag': 0
                }
            ]
        },
        'method_mapping': {
            'add': 'object0',
            'get': 'object1',
            'set': 'object0',
            'update': 'object0'
        }
    }

    module_arg_spec = {
        'loose_validation': {
            'type': 'bool',
            'required': False,
            'default': False
        },
        'workspace_locking_adom': {
            'type': 'str',
            'required': False
        },
        'workspace_locking_timeout': {
            'type': 'int',
            'required': False,
            'default': 300
        },
        'params': {
            'type': 'list',
            'required': False
        },
        'method': {
            'type': 'str',
            'required': True,
            'choices': [
                'add',
                'get',
                'set',
                'update'
            ]
        },
        'url_params': {
            'type': 'dict',
            'required': False
        }
    }
    module = AnsibleModule(argument_spec=module_arg_spec,
                           supports_check_mode=False)
    method = module.params['method']
    loose_validation = module.params['loose_validation']

    fmgr = None
    payload = None
    response = DEFAULT_RESULT_OBJ

    if module._socket_path:
        connection = Connection(module._socket_path)
        tools = FMGRCommon()
        if loose_validation is False:
            tools.validate_module_params(module, body_schema)
        tools.validate_module_url_params(module, jrpc_urls, url_schema)
        full_url = tools.get_full_url_path(module, jrpc_urls)
        payload = tools.get_full_payload(module, full_url)
        fmgr = FortiManagerHandler(connection, module)
        fmgr.tools = tools
    else:
        module.fail_json(**FAIL_SOCKET_MSG)

    try:
        response = fmgr._conn.send_request(method, payload)
        fmgr.govern_response(module=module, results=response,
                             msg='Operation Finished',
                             ansible_facts=fmgr.construct_ansible_facts(response, module.params, module.params))
    except Exception as e:
        raise FMGBaseException(e)

    module.exit_json(meta=response[1])


if __name__ == '__main__':
    main()
