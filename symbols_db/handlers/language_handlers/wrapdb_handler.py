import os
from pathlib import Path

from symbols_db import WRAPDB_LOCATION
from symbols_db.projects_compiler.meson import (
    git_checkout_wrapdb_commit,
    git_clone_wrapdb,
)


def get_wrapdb_projects():
    git_clone_wrapdb()
    git_checkout_wrapdb_commit()
    subproject_filenames = os.listdir(WRAPDB_LOCATION / "subprojects")
    projects_list = []
    for file in subproject_filenames:
        project_path = Path(file)
        if project_path.suffix == ".wrap":
            projects_list.append(project_path.stem)
    return projects_list
