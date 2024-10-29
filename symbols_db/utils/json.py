import json

from symbols_db import logger


def get_key_in_json_list(key_search, key_name, property_list):
    return_key = None
    for i in property_list:
        if i[key_name] == key_search:
            return_key = i
    if return_key:
        return return_key
    else:
        raise KeyError("Spelling mistake probably")


def property_exists_get_property(component, property_name):
    if properties := component.get("properties", {}):
        req_property = get_key_in_json_list(property_name, "name", properties)
        req_property = req_property["value"]
        return req_property
    else:
        return []


def get_properties_internal(property_name, file_name):
    blint_sbom = None
    with open(file_name, "r") as f:
        blint_sbom = json.load(f)

    component = blint_sbom["metadata"]["component"]

    if not (req_property := property_exists_get_property(component, property_name)):
        req_property_list = []
        if components := component.get("components", {}):
            req_property_list.extend(
                property_exists_get_property(comp, property_name) for comp in components
            )
        req_property = "~~".join(req_property_list)

    return req_property
