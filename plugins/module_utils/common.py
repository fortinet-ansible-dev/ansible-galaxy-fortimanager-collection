# This code is part of Ansible, but is an independent component.
# This particular file snippet, and this file snippet only, is BSD licensed.
# Modules you write using this snippet, which is embedded dynamically by Ansible
# still belong to the author of the module, and may assign their own license
# to the complete work.
#
# (c) 2017-2020 Fortinet, Inc
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
#    * Redistributions of source code must retain the above copyright
#      notice, this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above copyright notice,
#      this list of conditions and the following disclaimer in the documentation
#      and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
# USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
from __future__ import absolute_import, division, print_function

__metaclass__ = type


# BEGIN STATIC DATA / MESSAGES
class FMGRMethods:
    GET = "get"
    SET = "set"
    EXEC = "exec"
    EXECUTE = "exec"
    UPDATE = "update"
    ADD = "add"
    DELETE = "delete"
    REPLACE = "replace"
    CLONE = "clone"
    MOVE = "move"


BASE_HEADERS = {"Content-Type": "application/json", "Accept": "application/json"}


# FMGR RETURN CODES
FMGR_RC = {
    "fmgr_return_codes": {
        0: {"msg": "OK", "changed": True, "stop_on_success": True},
        -100000: {
            "msg": "Module returned without actually running anything. "
            "Check parameters, and please contact the authors if needed.",
            "failed": True,
        },
        -2: {
            "msg": "Object already exists.",
            "skipped": True,
            "changed": False,
            "good_codes": [0, -2],
        },
        -6: {
            "msg": "Invalid Url. Sometimes this can happen because the path is mapped to a hostname or object that"
            " doesn't exist. Double check your input object parameters."
        },
        -3: {
            "msg": "Object doesn't exist.",
            "skipped": True,
            "changed": False,
            "good_codes": [0, -3],
        },
        -10131: {
            "msg": "Object dependency failed. Do all named objects in parameters exist?",
            "changed": False,
            "skipped": True,
        },
        -9998: {
            "msg": "Duplicate object. Try using mode='set', if using add. STOPPING. Use 'ignore_errors=yes' in playbook"
            "to override and mark successful."
        },
        -20042: {"msg": "Device Unreachable.", "skipped": True},
        -10033: {
            "msg": "Duplicate object. Try using mode='set', if using add.",
            "changed": False,
            "skipped": True,
        },
        -10000: {
            "msg": "Duplicate object. Try using mode='set', if using add.",
            "changed": False,
            "skipped": True,
        },
        -20010: {
            "msg": "Device already added to FortiManager. Serial number already in use.",
            "good_codes": [0, -20010],
            "changed": False,
            "stop_on_success": True,
        },
        -20002: {
            "msg": "Invalid Argument -- Does this Device exist on FortiManager?",
            "changed": False,
            "skipped": True,
        },
    }
}

DEFAULT_RESULT_OBJ = (
    -100000,
    {"msg": "Nothing Happened. Check that handle_response is being called!"},
)
FAIL_SOCKET_MSG = {
    "msg": "Socket Path Empty! The persistent connection manager is messed up. "
    "Try again in a few moments."
}


# BEGIN ERROR EXCEPTIONS
class FMGBaseException(Exception):
    """Wrapper to catch the unexpected"""

    def __init__(self, msg=None, *args, **kwargs):
        if msg is None:
            msg = "An exception occurred within the fortimanager.py httpapi connection plugin."
        super(FMGBaseException, self).__init__(msg, *args)


# END ERROR CLASSES


# BEGIN CLASSES
class FMGRCommon(object):
    @staticmethod
    def format_request(method, url, *args, **kwargs):
        """
        Formats the payload from the module, into a payload the API handler can use.

        :param url: Connection URL to access
        :type url: string
        :param method: The preferred API Request method (GET, ADD, POST, etc....)
        :type method: basestring
        :param kwargs: The payload dictionary from the module to be converted.

        :return: Properly formatted dictionary payload for API Request via Connection Plugin.
        :rtype: dict
        """

        params = [{"url": url}]
        if args:
            for arg in args:
                params[0].update(arg)
        if kwargs:
            keylist = list(kwargs)
            for k in keylist:
                kwargs[k.replace("__", "-")] = kwargs.pop(k)
            if method == "get" or method == "clone":
                params[0].update(kwargs)
            else:
                if kwargs.get("data", False):
                    params[0]["data"] = kwargs["data"]
                else:
                    params[0]["data"] = kwargs
        return params

    @staticmethod
    def split_comma_strings_into_lists(obj):
        """
        Splits a CSV String into a list.  Also takes a dictionary, and converts any CSV strings in any key, to a list.

        :param obj: object in CSV format to be parsed.
        :type obj: str or dict

        :return: A list containing the CSV items.
        :rtype: list
        """
        return_obj = ()
        if isinstance(obj, dict):
            if len(obj) > 0:
                for k, v in obj.items():
                    if isinstance(v, str):
                        new_list = list()
                        if "," in v:
                            new_items = v.split(",")
                            for item in new_items:
                                new_list.append(item.strip())
                            obj[k] = new_list
                return_obj = obj
        elif isinstance(obj, str):
            return_obj = obj.replace(" ", "").split(",")

        return return_obj

    @staticmethod
    def cidr_to_netmask(cidr):
        """
        Converts a CIDR Network string to full blown IP/Subnet format in decimal format.
        Decided not use IP Address module to keep includes to a minimum.

        :param cidr: String object in CIDR format to be processed
        :type cidr: str

        :return: A string object that looks like this "x.x.x.x/y.y.y.y"
        :rtype: str
        """
        if isinstance(cidr, str):
            cidr = int(cidr)
            mask = (0xFFFFFFFF >> (32 - cidr)) << (32 - cidr)
            return (
                str((0xFF000000 & mask) >> 24)
                + "."
                + str((0xFF0000 & mask) >> 16)
                + "."
                + str((0x0000FF00 & mask) >> 8)
                + "."
                + str((0x000000FF & mask))
            )

    @staticmethod
    def paramgram_child_list_override(list_overrides, paramgram, module):
        """
        If a list of items was provided to a "parent" paramgram attribute, the paramgram needs to be rewritten.
        The child keys of the desired attribute need to be deleted, and then that "parent" keys' contents is replaced
        With the list of items that was provided.

        :param list_overrides: Contains the response from the FortiManager.
        :type list_overrides: list
        :param paramgram: Contains the paramgram passed to the modules' local modify function.
        :type paramgram: dict
        :param module: Contains the Ansible Module Object being used by the module.
        :type module: classObject

        :return: A new "paramgram" refactored to allow for multiple entries being added.
        :rtype: dict
        """
        if len(list_overrides) > 0:
            for list_variable in list_overrides:
                try:
                    list_variable = list_variable.replace("-", "_")
                    override_data = module.params[list_variable]
                    if override_data:
                        del paramgram[list_variable]
                        paramgram[list_variable] = override_data
                except BaseException as e:
                    raise FMGBaseException(
                        "Error occurred merging custom lists for the paramgram parent: "
                        + str(e)
                    )
        return paramgram

    @staticmethod
    def syslog(module, msg):
        try:
            module.log(msg=msg)
        except BaseException:
            pass

    def _report_schema_violation(self, param, schema, detail):
        """
        the helper function which fortmats the error message.

        :param param: the parameters which are going to be matched.
        :type param: dict
        :param schema: the schemas which are going to be matched with.
        :type schema: dict
        :param detail: the hint message which reveals the sort of violation message.
        :type detail: string

        :return: the status along with formatted error message string
        :rtype: tuple
        """
        return (
            False,
            "param:%s does not match schema:%s, detail:%s" % (param, schema, detail),
        )

    def _validate_param_recursivly(self, param, schema):
        """
        the routine which recursively validate the provided parameters and schemas.

        :param param: the parameters which are going to be matched.
        :type param: dict
        :param schema: the schemas which are going to be matched with.
        :type schema: dict

        :return: the status along with formatted error message string
        :rtype: tuple
        """
        param_key = None if not isinstance(param, dict) else list(param.keys())[0]
        param_value = param if not isinstance(param, dict) else param[param_key]

        if "type" not in schema or schema["type"] not in [
            "string",
            "integer",
            "array",
            "dict",
        ]:
            if not isinstance(param, dict) or not isinstance(schema, dict):
                return self._report_schema_violation(
                    param, schema, "unrecognized failure"
                )
            for discrete_param_key in param:
                discrete_param_value = param[discrete_param_key]
                if discrete_param_key not in schema and (
                    len(schema) != 1
                    or not list(schema.keys())[0].startswith("{")
                    or not list(schema.keys())[0].endswith("}")
                ):
                    return self._report_schema_violation(
                        discrete_param_key, schema, "no available schema found"
                    )
                per_param_schema = schema[list(schema.keys())[0]]
                if discrete_param_key in schema:
                    per_param_schema = schema[discrete_param_key]
                result, message = self._validate_param_recursivly(
                    discrete_param_value, per_param_schema
                )
                if not result:
                    return result, message
            return True, ""

        if schema["type"] == "string":
            if not isinstance(param_value, str):
                return self._report_schema_violation(param, schema, "type mismatch")
            if "enum" in schema and param_value not in schema["enum"]:
                return self._report_schema_violation(
                    param, schema, "enum value mismatch"
                )
        elif schema["type"] == "integer":
            if not isinstance(param_value, int):
                return self._report_schema_violation(param, schema, "type mismatch")
            if "enum" in schema and param_value not in schema["enum"]:
                return self._report_schema_violation(
                    param, schema, "enum value mismatch"
                )
        elif schema["type"] == "array":
            if "items" not in schema:
                raise AssertionError("'items' not in schema:%s" % (schema))
            if not isinstance(param_value, list):
                return self._report_schema_violation(param, schema, "type mismatch")
            for elem in param_value:
                result, message = self._validate_param_recursivly(elem, schema["items"])
                if not result:
                    return result, message
        elif schema["type"] == "dict":
            if not isinstance(param, dict):
                return self._report_schema_violation(param, schema, "type mismatch")
            if len(list(param.keys())) != 1 or list(param.keys())[0] != schema["name"]:
                return self._report_schema_violation(
                    param, schema, "schema content mismatch"
                )
            if "dict" not in schema:
                raise AssertionError("'dict' not in schema:%s" % (schema))
            return self._validate_param_recursivly(
                param[schema["name"]], schema["dict"]
            )
        return True, ""

    def _validate_param_block(self, param_block, tagged_schema):
        """
        the subordinate routines to validate a tagged parameter block

        :param param_block: the tagged parameters block which are going to be matched.
        :type param_block: dict
        :param tagged_schema: the tagged schemas which are going to be matched with.
        :type tagged_schema: dict

        :return: the status along with formatted error message string
        :rtype: tuple
        """
        for param_item_name in param_block:
            param_item = {param_item_name: param_block[param_item_name]}
            schema_item = None
            for schema_desc in tagged_schema:
                if schema_desc["name"] == param_item_name:
                    schema_item = schema_desc
                    break
            if not schema_item:
                return False, "unrecognized parameter: %s" % (param_item_name)
            result, message = self._validate_param_recursivly(param_item, schema_item)
            if not result:
                return result, message
        return True, "parameter block validation succeeds"

    def validate_module_params(self, module, schemas):
        """
        the routine to validate input parameters.

        :param module: the Ansible module structure.
        :type module: AnsibleModule
        :param schemas: the schemas which are going to be matched with.
        :type schemas: dict

        :return: the status along with formatted error message string
        :rtype: tuple
        """
        method = module.params["method"]

        # categorize schema item according to its api_tag.
        if method not in schemas["method_mapping"]:
            raise FMGBaseException("method:%s not supported in schema" % (method))
        schema = schemas["schema_objects"][schemas["method_mapping"][method]]

        tagged_schemas = dict()
        for item in schema:
            if item["name"] == "url":
                continue
            api_tag = item["api_tag"]
            if api_tag not in tagged_schemas:
                tagged_schemas[api_tag] = list()
            tagged_schemas[api_tag].append(item)
        # if no parameters, we skip the validation phase
        if not module.params["params"]:
            return

        for param_block in module.params["params"]:
            # in case there are more than one api tag for the url, we check it one by one
            # until we encounter an explicit failure
            validation_result = False
            validation_message = None
            for tagged_schema_key in tagged_schemas:
                tagged_schema = tagged_schemas[tagged_schema_key]
                result, message = self._validate_param_block(param_block, tagged_schema)
                validation_result |= result
                if not result:
                    validation_message = message
                else:
                    break
            if not validation_result:
                raise FMGBaseException(
                    "parameter validation fails: %s" % (validation_message)
                )

    def validate_module_url_params(self, module, jrpc_urls, raw_url_schema):
        """
        validate whether the given paramters in url match their schema counterpart.

        :param module: the Ansible module structure.
        :type module: AnsibleModule
        :param jrpc_urls: the parameters in url
        :type jrpc_urls: list
        :param raw_url_schema: the schemas to be matched with.
        :type raw_url_schema: list

        :return: None
        :rtype: Exception maybe raised.
        """
        raw_url_params = module.params["url_params"]
        # if no url_schema is provided, it's a solo url_no_domain
        if not len(raw_url_schema):
            if raw_url_params and len(raw_url_params):
                raise FMGBaseException("the module expects no url params")
            else:
                return

        url_schema = list()
        url_params = dict()
        adom_value = "none"
        if "adom" in adom_value:
            adom_value = raw_url_params["adom"].lower()

        if adom_value == "none" or adom_value == "global":
            for item in raw_url_schema:
                if item["name"] == "adom":
                    continue
                url_schema.append(item)
            for param_key in raw_url_params:
                if param_key == "adom":
                    continue
                url_params[param_key] = raw_url_params[param_key]
        else:
            url_schema = raw_url_schema
            url_params = raw_url_params
        # do legacy validation.
        if not len(url_schema):
            return

        if not url_params or len(url_params) != len(url_schema):
            raise FMGBaseException(
                "mismatched pameters, full list:%s"
                % ([item["name"] for item in url_schema])
            )
        param_key_set = set(list(url_params.keys()))
        schema_key_set = set([item["name"] for item in url_schema])
        if param_key_set != schema_key_set:
            raise FMGBaseException(
                "url parameter %s does not match schema %s"
                % (param_key_set, schema_key_set)
            )
        for param_key in url_params:
            param = url_params[param_key]
            schema = None
            for schema_item in url_schema:
                if schema_item["name"] == param_key:
                    schema = schema_item
                    break
            if not schema:
                raise AssertionError("'schema' is None")
            if (
                schema["type"] == "string"
                and not isinstance(param, str)
                or schema["type"] == "integer"
                and not isinstance(param, int)
            ):
                raise FMGBaseException(
                    "url parameter %s does not schema %s" % (param, schema)
                )

    def get_full_url_path(self, module, jrpc_urls):
        """
        format the full url string for json-rpc.

        :param module: the Ansible module structure.
        :type module: AnsibleModule
        :param jrpc_urls: the parameters in url
        :type jrpc_urls: list

        :return: the url string.
        :rtype: string
        """
        url_params = module.params["url_params"]
        url_custom_domain = None
        url_global_domain = None
        url_no_domain = None
        url_format = None
        for _url in jrpc_urls:
            if "/adom/{adom}/" in _url or _url.endswith("/adom/{adom}"):
                url_custom_domain = _url
            elif "/global/" in _url:
                url_global_domain = _url
            else:
                url_no_domain = _url
        if not url_params or "adom" not in url_params:
            url_format = url_no_domain
        elif url_params["adom"] == "global":
            url_format = url_global_domain
        elif url_params["adom"] == "none":
            url_format = url_no_domain
        else:
            url_format = url_custom_domain
        if not url_format:
            raise AssertionError("'url_format' is None")
        return url_format if not url_params else url_format.format(**url_params)

    def get_full_payload(self, module, full_url):
        """
        construct the full payload including url for json-rpc

        :param module: the Ansible module structure.
        :type module: AnsibleModule
        :param jrpc_urls: the parameters in url
        :type jrpc_urls: list

        :return: the payload list
        :rtype: list
        """
        payload_list = list()
        params_blocks = module.params["params"]
        if params_blocks:
            for params_block in params_blocks:
                payload = dict()
                payload["url"] = full_url
                for top_level_param_key in params_block:
                    top_level_param = params_block[top_level_param_key]
                    payload[top_level_param_key] = top_level_param
                payload_list.append(payload)
        else:
            # There is one exception that no params is provided, the url is only one in the request
            payload_list.append({"url": full_url})
        return payload_list


# RECURSIVE FUNCTIONS START
def prepare_dict(obj):
    """
    Removes any keys from a dictionary that are only specific to our use in the module. FortiManager will reject
    requests with these empty/None keys in it.

    :param obj: Dictionary object to be processed.
    :type obj: dict

    :return: Processed dictionary.
    :rtype: dict
    """

    list_of_elems = ["mode", "adom", "host", "username", "password"]

    if isinstance(obj, dict):
        obj = dict(
            (key, prepare_dict(value))
            for (key, value) in obj.items()
            if key not in list_of_elems
        )
    return obj


def scrub_dict(obj):
    """
    Removes any keys from a dictionary that are EMPTY -- this includes parent keys. FortiManager doesn't
    like empty keys in dictionaries

    :param obj: Dictionary object to be processed.
    :type obj: dict

    :return: Processed dictionary.
    :rtype: dict
    """

    if isinstance(obj, dict):
        return dict((k, scrub_dict(v)) for k, v in obj.items() if v and scrub_dict(v))
    else:
        return obj
