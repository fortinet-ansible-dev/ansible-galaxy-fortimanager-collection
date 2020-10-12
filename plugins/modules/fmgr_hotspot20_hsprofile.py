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
module: fmgr_hotspot20_hsprofile
short_description: Configure hotspot profile.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.10"
author:
    - Link Zheng (@chillancezen)
    - Jie Xue (@JieX19)
    - Frank Shen (@fshen01)
    - Hongbin Lu (@fgtdev-hblu)
notes:
    - Running in workspace locking mode is supported in this FortiManager module, the top
      level parameters workspace_locking_adom and workspace_locking_timeout help do the work.
    - To create or update an object, use state present directive.
    - To delete an object, use state absent directive.
    - Normally, running one module can fail when a non-zero rc is returned. you can also override
      the conditions to fail or succeed with parameters rc_failed and rc_succeeded

options:
    bypass_validation:
        description: only set to True when module schema diffs with FortiManager API structure, module continues to execute without validating parameters
        required: false
        type: bool
        default: false
    workspace_locking_adom:
        description: the adom to lock for FortiManager running in workspace mode, the value can be global and others including root
        required: false
        type: str
    workspace_locking_timeout:
        description: the maximum time in seconds to wait for other user to release the workspace lock
        required: false
        type: int
        default: 300
    state:
        description: the directive to create, update or delete an object
        type: str
        required: true
        choices:
          - present
          - absent
    rc_succeeded:
        description: the rc codes list with which the conditions to succeed will be overriden
        type: list
        required: false
    rc_failed:
        description: the rc codes list with which the conditions to fail will be overriden
        type: list
        required: false
    adom:
        description: the parameter (adom) in requested url
        type: str
        required: true
    hotspot20_hsprofile:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            3gpp-plmn:
                type: str
                description: '3GPP PLMN name.'
            access-network-asra:
                type: str
                description: 'Enable/disable additional step required for access (ASRA).'
                choices:
                    - 'disable'
                    - 'enable'
            access-network-esr:
                type: str
                description: 'Enable/disable emergency services reachable (ESR).'
                choices:
                    - 'disable'
                    - 'enable'
            access-network-internet:
                type: str
                description: 'Enable/disable connectivity to the Internet.'
                choices:
                    - 'disable'
                    - 'enable'
            access-network-type:
                type: str
                description: 'Access network type.'
                choices:
                    - 'private-network'
                    - 'private-network-with-guest-access'
                    - 'chargeable-public-network'
                    - 'free-public-network'
                    - 'personal-device-network'
                    - 'emergency-services-only-network'
                    - 'test-or-experimental'
                    - 'wildcard'
            access-network-uesa:
                type: str
                description: 'Enable/disable unauthenticated emergency service accessible (UESA).'
                choices:
                    - 'disable'
                    - 'enable'
            anqp-domain-id:
                type: int
                description: 'ANQP Domain ID (0-65535).'
            bss-transition:
                type: str
                description: 'Enable/disable basic service set (BSS) transition Support.'
                choices:
                    - 'disable'
                    - 'enable'
            conn-cap:
                type: str
                description: 'Connection capability name.'
            deauth-request-timeout:
                type: int
                description: 'Deauthentication request timeout (in seconds).'
            dgaf:
                type: str
                description: 'Enable/disable downstream group-addressed forwarding (DGAF).'
                choices:
                    - 'disable'
                    - 'enable'
            domain-name:
                type: str
                description: 'Domain name.'
            gas-comeback-delay:
                type: int
                description: 'GAS comeback delay (0 or 100 - 4000 milliseconds, default = 500).'
            gas-fragmentation-limit:
                type: int
                description: 'GAS fragmentation limit (512 - 4096, default = 1024).'
            hessid:
                type: str
                description: 'Homogeneous extended service set identifier (HESSID).'
            ip-addr-type:
                type: str
                description: 'IP address type name.'
            l2tif:
                type: str
                description: 'Enable/disable Layer 2 traffic inspection and filtering.'
                choices:
                    - 'disable'
                    - 'enable'
            nai-realm:
                type: str
                description: 'NAI realm list name.'
            name:
                type: str
                description: 'Hotspot profile name.'
            network-auth:
                type: str
                description: 'Network authentication name.'
            oper-friendly-name:
                type: str
                description: 'Operator friendly name.'
            osu-provider:
                type: str
                description: 'Manually selected list of OSU provider(s).'
            osu-ssid:
                type: str
                description: 'Online sign up (OSU) SSID.'
            pame-bi:
                type: str
                description: 'Enable/disable Pre-Association Message Exchange BSSID Independent (PAME-BI).'
                choices:
                    - 'disable'
                    - 'enable'
            proxy-arp:
                type: str
                description: 'Enable/disable Proxy ARP.'
                choices:
                    - 'disable'
                    - 'enable'
            qos-map:
                type: str
                description: 'QoS MAP set ID.'
            roaming-consortium:
                type: str
                description: 'Roaming consortium list name.'
            venue-group:
                type: str
                description: 'Venue group.'
                choices:
                    - 'unspecified'
                    - 'assembly'
                    - 'business'
                    - 'educational'
                    - 'factory'
                    - 'institutional'
                    - 'mercantile'
                    - 'residential'
                    - 'storage'
                    - 'utility'
                    - 'vehicular'
                    - 'outdoor'
            venue-name:
                type: str
                description: 'Venue name.'
            venue-type:
                type: str
                description: 'Venue type.'
                choices:
                    - 'unspecified'
                    - 'arena'
                    - 'stadium'
                    - 'passenger-terminal'
                    - 'amphitheater'
                    - 'amusement-park'
                    - 'place-of-worship'
                    - 'convention-center'
                    - 'library'
                    - 'museum'
                    - 'restaurant'
                    - 'theater'
                    - 'bar'
                    - 'coffee-shop'
                    - 'zoo-or-aquarium'
                    - 'emergency-center'
                    - 'doctor-office'
                    - 'bank'
                    - 'fire-station'
                    - 'police-station'
                    - 'post-office'
                    - 'professional-office'
                    - 'research-facility'
                    - 'attorney-office'
                    - 'primary-school'
                    - 'secondary-school'
                    - 'university-or-college'
                    - 'factory'
                    - 'hospital'
                    - 'long-term-care-facility'
                    - 'rehab-center'
                    - 'group-home'
                    - 'prison-or-jail'
                    - 'retail-store'
                    - 'grocery-market'
                    - 'auto-service-station'
                    - 'shopping-mall'
                    - 'gas-station'
                    - 'private'
                    - 'hotel-or-motel'
                    - 'dormitory'
                    - 'boarding-house'
                    - 'automobile'
                    - 'airplane'
                    - 'bus'
                    - 'ferry'
                    - 'ship-or-boat'
                    - 'train'
                    - 'motor-bike'
                    - 'muni-mesh-network'
                    - 'city-park'
                    - 'rest-area'
                    - 'traffic-control'
                    - 'bus-stop'
                    - 'kiosk'
            wan-metrics:
                type: str
                description: 'WAN metric name.'
            wnm-sleep-mode:
                type: str
                description: 'Enable/disable wireless network management (WNM) sleep mode.'
                choices:
                    - 'disable'
                    - 'enable'

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
    - name: Configure hotspot profile.
      fmgr_hotspot20_hsprofile:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         state: <value in [present, absent]>
         hotspot20_hsprofile:
            3gpp-plmn: <value of string>
            access-network-asra: <value in [disable, enable]>
            access-network-esr: <value in [disable, enable]>
            access-network-internet: <value in [disable, enable]>
            access-network-type: <value in [private-network, private-network-with-guest-access, chargeable-public-network, ...]>
            access-network-uesa: <value in [disable, enable]>
            anqp-domain-id: <value of integer>
            bss-transition: <value in [disable, enable]>
            conn-cap: <value of string>
            deauth-request-timeout: <value of integer>
            dgaf: <value in [disable, enable]>
            domain-name: <value of string>
            gas-comeback-delay: <value of integer>
            gas-fragmentation-limit: <value of integer>
            hessid: <value of string>
            ip-addr-type: <value of string>
            l2tif: <value in [disable, enable]>
            nai-realm: <value of string>
            name: <value of string>
            network-auth: <value of string>
            oper-friendly-name: <value of string>
            osu-provider: <value of string>
            osu-ssid: <value of string>
            pame-bi: <value in [disable, enable]>
            proxy-arp: <value in [disable, enable]>
            qos-map: <value of string>
            roaming-consortium: <value of string>
            venue-group: <value in [unspecified, assembly, business, ...]>
            venue-name: <value of string>
            venue-type: <value in [unspecified, arena, stadium, ...]>
            wan-metrics: <value of string>
            wnm-sleep-mode: <value in [disable, enable]>

'''

RETURN = '''
request_url:
    description: The full url requested
    returned: always
    type: str
    sample: /sys/login/user
response_code:
    description: The status of api request
    returned: always
    type: int
    sample: 0
response_message:
    description: The descriptive message of the api response
    type: str
    returned: always
    sample: OK.

'''
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import NAPIManager
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import check_galaxy_version
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import check_parameter_bypass


def main():
    jrpc_urls = [
        '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/hs-profile',
        '/pm/config/global/obj/wireless-controller/hotspot20/hs-profile'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/hs-profile/{hs-profile}',
        '/pm/config/global/obj/wireless-controller/hotspot20/hs-profile/{hs-profile}'
    ]

    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'bypass_validation': {
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
        'rc_succeeded': {
            'required': False,
            'type': 'list'
        },
        'rc_failed': {
            'required': False,
            'type': 'list'
        },
        'state': {
            'type': 'str',
            'required': True,
            'choices': [
                'present',
                'absent'
            ]
        },
        'adom': {
            'required': True,
            'type': 'str'
        },
        'hotspot20_hsprofile': {
            'required': False,
            'type': 'dict',
            'options': {
                '3gpp-plmn': {
                    'required': False,
                    'type': 'str'
                },
                'access-network-asra': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'access-network-esr': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'access-network-internet': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'access-network-type': {
                    'required': False,
                    'choices': [
                        'private-network',
                        'private-network-with-guest-access',
                        'chargeable-public-network',
                        'free-public-network',
                        'personal-device-network',
                        'emergency-services-only-network',
                        'test-or-experimental',
                        'wildcard'
                    ],
                    'type': 'str'
                },
                'access-network-uesa': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'anqp-domain-id': {
                    'required': False,
                    'type': 'int'
                },
                'bss-transition': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'conn-cap': {
                    'required': False,
                    'type': 'str'
                },
                'deauth-request-timeout': {
                    'required': False,
                    'type': 'int'
                },
                'dgaf': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'domain-name': {
                    'required': False,
                    'type': 'str'
                },
                'gas-comeback-delay': {
                    'required': False,
                    'type': 'int'
                },
                'gas-fragmentation-limit': {
                    'required': False,
                    'type': 'int'
                },
                'hessid': {
                    'required': False,
                    'type': 'str'
                },
                'ip-addr-type': {
                    'required': False,
                    'type': 'str'
                },
                'l2tif': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'nai-realm': {
                    'required': False,
                    'type': 'str'
                },
                'name': {
                    'required': True,
                    'type': 'str'
                },
                'network-auth': {
                    'required': False,
                    'type': 'str'
                },
                'oper-friendly-name': {
                    'required': False,
                    'type': 'str'
                },
                'osu-provider': {
                    'required': False,
                    'type': 'str'
                },
                'osu-ssid': {
                    'required': False,
                    'type': 'str'
                },
                'pame-bi': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'proxy-arp': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'qos-map': {
                    'required': False,
                    'type': 'str'
                },
                'roaming-consortium': {
                    'required': False,
                    'type': 'str'
                },
                'venue-group': {
                    'required': False,
                    'choices': [
                        'unspecified',
                        'assembly',
                        'business',
                        'educational',
                        'factory',
                        'institutional',
                        'mercantile',
                        'residential',
                        'storage',
                        'utility',
                        'vehicular',
                        'outdoor'
                    ],
                    'type': 'str'
                },
                'venue-name': {
                    'required': False,
                    'type': 'str'
                },
                'venue-type': {
                    'required': False,
                    'choices': [
                        'unspecified',
                        'arena',
                        'stadium',
                        'passenger-terminal',
                        'amphitheater',
                        'amusement-park',
                        'place-of-worship',
                        'convention-center',
                        'library',
                        'museum',
                        'restaurant',
                        'theater',
                        'bar',
                        'coffee-shop',
                        'zoo-or-aquarium',
                        'emergency-center',
                        'doctor-office',
                        'bank',
                        'fire-station',
                        'police-station',
                        'post-office',
                        'professional-office',
                        'research-facility',
                        'attorney-office',
                        'primary-school',
                        'secondary-school',
                        'university-or-college',
                        'factory',
                        'hospital',
                        'long-term-care-facility',
                        'rehab-center',
                        'group-home',
                        'prison-or-jail',
                        'retail-store',
                        'grocery-market',
                        'auto-service-station',
                        'shopping-mall',
                        'gas-station',
                        'private',
                        'hotel-or-motel',
                        'dormitory',
                        'boarding-house',
                        'automobile',
                        'airplane',
                        'bus',
                        'ferry',
                        'ship-or-boat',
                        'train',
                        'motor-bike',
                        'muni-mesh-network',
                        'city-park',
                        'rest-area',
                        'traffic-control',
                        'bus-stop',
                        'kiosk'
                    ],
                    'type': 'str'
                },
                'wan-metrics': {
                    'required': False,
                    'type': 'str'
                },
                'wnm-sleep-mode': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'hotspot20_hsprofile'),
                           supports_check_mode=False)

    fmgr = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        fmgr = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection, top_level_schema_name='data')
        fmgr.validate_parameters(params_validation_blob)
        fmgr.process_curd()
    else:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
