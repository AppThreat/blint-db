# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT

import json

from tests.scripts.match_internal_functions_withdb import get_pname_bname

with open("all_ifunc_object.json", "r") as f:
    all_func = json.load(f)

project_list = []

for key in all_func:
    if len(data := all_func[key]):
        # print(data)
        for bname in data:
            pname = get_pname_bname(bname)
            project_list.append(pname)

print(set(project_list))
