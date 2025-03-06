# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT

import subprocess


def git_clone(git_url, loc):
    # TODO: error checking here
    # TODO: handle and print output of command
    command = ["git", "clone", git_url, loc]
    subprocess.run(command, capture_output=True, check=False, encoding="utf-8")


def git_checkout_commit(loc, commit_hash):
    command = ["git", "-C", loc, "checkout", commit_hash]
    subprocess.run(command, capture_output=True, check=False, encoding="utf-8")
