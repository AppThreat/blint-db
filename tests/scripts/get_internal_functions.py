import argparse
import concurrent
import concurrent.futures
import json

from blint_db.handlers.blint_handler import get_properties_internal
from tests.scripts.match_internal_functions_withdb import (get_bid_using_fid,
                                                           get_bname,
                                                           get_export_id)


def arguments_parser():
    parser = argparse.ArgumentParser(
        prog="script to check performance of blint_db",
        description="Checks if stored symbols are matching",
    )
    parser.add_argument(
        "-b",
        "--blint-deep-sbom",
        dest="bom",
        help="Path to the BLINT sbom run with --deep argument",
    )
    parser.add_argument(
        "--single-threaded",
        dest="single",
        default=False,
        help="Path to the BLINT sbom run with --deep argument",
    )
    return parser.parse_args()


def get_blint_internal_functions(file_name):
    if_string = get_properties_internal("internal:functions", file_name).split("~~")
    return if_string


def get_bnames_ename(i_func):
    bin_names = []
    eid = get_export_id(i_func)
    bid_list = get_bid_using_fid(eid)
    if bid_list:
        for bid in bid_list:
            bin_names.append(get_bname(bid))
    return bin_names


def main():
    # this function takes blint deep sbom for working
    args = vars(arguments_parser())

    print(args)

    if bom_file := args["bom"]:
        all_ifunc_object = {}
        if_strings = get_blint_internal_functions(bom_file)
        if args["single"]:
            for i_func in if_strings:
                bin_names = get_bnames_ename(i_func)
                print_string = f"For func: {i_func} got binaries: {bin_names}"
                all_ifunc_object[i_func] = bin_names
                if bin_names:
                    print(print_string)
        else:
            with concurrent.futures.ProcessPoolExecutor(max_workers=4) as executor:
                for func_name, bin_names in zip(
                    if_strings, executor.map(get_bnames_ename, if_strings)
                ):
                    print_string = f"For func: {func_name} got binaries: {bin_names}"
                    all_ifunc_object[func_name] = bin_names
                    if bin_names:
                        print(print_string)

        with open("all_ifunc_object.json", "w") as f:
            json.dump(all_ifunc_object, f)


if __name__ == "__main__":
    main()
