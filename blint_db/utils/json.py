# SPDX-FileCopyrightText: 2024 AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT

import json


def get_key_in_json_list(key_search, key_name, property_list):
    return_key = ""
    for i in property_list:
        if i[key_name] == key_search:
            return_key = i
    return return_key if return_key else {"value": ""}


def property_exists_get_property(component, property_name):
    if properties := component.get("properties", {}):
        req_property = get_key_in_json_list(property_name, "name", properties)
        req_property = req_property["value"]
        return req_property
    else:
        return ""


def get_properties_internal(property_name, file_name):
    with open(file_name, "r") as f:
        blint_sbom = json.load(f)

    component = blint_sbom["metadata"]["component"]

    if not (req_property := property_exists_get_property(component, property_name)):
        req_property_list = []
        if comp_list := component.get("components", {}):
            req_property_list.extend(
                property_exists_get_property(comp, property_name) for comp in comp_list
            )
        req_property = "~~".join(req_property_list)

    return req_property
