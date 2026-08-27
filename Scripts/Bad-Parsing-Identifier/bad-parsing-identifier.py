from dotenv import dotenv_values
import requests
import csv
import json
import datetime
import gzip
import base64
import time
import concurrent.futures
import argparse
import sys
from colorama import Fore, Style, init
from urllib.parse import quote

def get_config_from_args():
    """Parses command-line arguments and returns a configuration dictionary."""
    parser = argparse.ArgumentParser(
        description="Identify potential bad parsing in Exabeam by running a series of predefined searches."
    )
    parser.add_argument("region", help="The Exabeam cloud region (e.g., us-west, us-east, ca).")
    parser.add_argument("env_name", help="The name of your Exabeam environment.")
    parser.add_argument(
        "token_file", help="The path to your .env file containing API credentials."
    )
    parser.add_argument(
        "--prefix",
        help="An optional search prefix to prepend to all queries (e.g., 'vendor==\"My Vendor\" AND ').",
        default="",
        nargs="?",
    )
    parser.add_argument(
        "--threads",
        help="The number of concurrent searches to run. Defaults to 10 threads.",
        type=int,
        default=10,
    )
    args = parser.parse_args()

    if args.prefix:
        full_prefix = args.prefix + " AND "
    else:
        full_prefix = ""

    return {
        "region": args.region,
        "env_name": args.env_name,
        "token_file": args.token_file,
        "prefix": full_prefix,
        "max_workers": args.threads,
    }


def get_bearer_token(config):
    url = f"https://api.{config['region']}.exabeam.cloud/auth/v1/token"
    try:
        env_vars = dotenv_values(config["token_file"])
        client_id = env_vars["CLIENT_ID"]
        client_secret = env_vars["CLIENT_SECRET"]
    except KeyError as e:
        print(f"{Fore.RED}Error: Key {e} was not found in token file '{config['token_file']}'.")
        sys.exit(-1)
    except Exception as e:
        print(f"{Fore.RED}Error loading token file '{config['token_file']}': {e}")
        sys.exit(-1)

    payload = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
    }
    headers = {"accept": "application/json", "content-type": "application/json"}
    response = requests.post(url, json=payload, headers=headers)
    if response.status_code != 200:
        print(f"{Fore.RED}Something went wrong getting the access token: \n{response.text}")
        print(
            f"{Fore.RED}Your region may be selected incorrectly or your env file may be structured improperly."
        )
        sys.exit(-1)
    print(f"{Fore.GREEN}Successfully obtained access token.")
    return json.loads(response.text).get("access_token")


def _get_region_url_specifier(region):
    region_mapping = {
        "us-west": "",
        "us-east": ".use1",
        "ca": ".ca",
        "sg": ".sg",
        "jp": ".jp",
        "eu": ".eu",
        "au": ".au",
        "ch": ".ch",
        "sa": ".sa",
        "uk": ".uk",
    }
    if region in region_mapping:
        return region_mapping[region]

    print(f"{Fore.YELLOW}Warning: Region code specifier could not be resolved for region: '{region}'. Defaulting to empty specifier.")
    return ""


def _execute_search(session, search_query, config, start_time, end_time):
    """Executes a single search query and reports if bad parsing is found."""
    full_query = config["prefix"] + search_query
    payload = {
        "fields": ["time"],
        "limit": 100,
        "distinct": False,
        "startTime": start_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "endTime": end_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "filter": full_query,
    }

    print(f"{Fore.CYAN}Testing search: {full_query}...")
    response = session.post(
        url=f"https://api.{config['region']}.exabeam.cloud/search/v2/events",
        data=json.dumps(payload),
    )

    if response.status_code != 200:
        print(
            f"{Fore.RED}Something went wrong with the search: {response.text} --- Search: {full_query}"
        )
        return

    if json.loads(response.text).get("totalRows") > 0:
        print(
            f"{Fore.LIGHTYELLOW_EX}{Style.BRIGHT}[!] Bad parsing identified for search {full_query}"
        )
        search_json = {
            "currQuery": full_query,
            "timeRange": {
                "from": start_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "to": end_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "quickRange": "",
                "type": "absolute",
            },
        }
        str_search_json = json.dumps(search_json)
        gzip_compressed_search_json = gzip.compress(str_search_json.encode("ascii"))
        b64_search_json = base64.b64encode(gzip_compressed_search_json).decode("ascii")
        url_encoded_search_json = quote(b64_search_json, safe="")
        search_url = f"https://{config['env_name']}{_get_region_url_specifier(config['region'])}.exabeam.cloud/app/search/query/results#z_{url_encoded_search_json}"
        print(f"{Fore.YELLOW}Link to logs: {search_url}")
        return {"query": full_query, "url": search_url}


def run_searches(config, token):
    end_time = datetime.datetime.now(datetime.timezone.utc)
    start_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(
        days=7
    )
    searches = [
        r'NOT user: null AND (user=="-" OR user=="na" OR user=="LOCAL")',
        r'NOT user: null AND user: RGX("[\\\/\[\]@\'\"\|]+")',
        r'NOT email_address: null AND NOT email_address: WLD("*@*")',
        r'NOT email_address: null AND ( email_address=="-" OR email_address=="na")',
        r'NOT email_address: null AND email_address: RGX("[\\\/\(\)]+")',
        r'NOT process_name: null AND process_name == "Program"',
        r'NOT process_name: null AND process_name == "-"',
        r'NOT process_path: null AND process_path: RGXi(".*Program$")',
        r'NOT process_path: null AND process_path== "-"',
        r'dns_query== "NA"',
        r'dns_query: RGX("[\\\/\[\]@\'\"\|]+")',
        r'dest_host:RGXi("^[\W_]+") OR dest_host:RGX("[\\\/\[\]@\'\"\|]+")',
        r'src_host:RGXi("^[\W_]+") OR src_host:RGX("[\\\/\[\]@\'\"\|]+")',
        r'host:RGXi("^[\W_]+") OR host:RGX("[\\\/\[\]@\'\"\|]+")',
        r"NOT error_detail:null",
        r'user:RGXi("^.{1,3}$")',
    ]

    bad_parsing_findings = []

    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "Authorization": f"Bearer {token}",
    }

    with requests.Session() as session:
        session.headers.update(headers)
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=config["max_workers"]
        ) as executor:
            # Schedule each search to be run in a separate thread
            future_to_search = {
                executor.submit(
                    _execute_search, session, search, config, start_time, end_time
                ): search
                for search in searches
            }
            for future in concurrent.futures.as_completed(future_to_search):
                search = future_to_search[future]
                try:
                    # future.result() blocks until the function is complete and returns its value.
                    result = future.result()
                    if result:
                        bad_parsing_findings.append(result)
                except Exception as exc:
                    print(f"{Fore.RED}{search} generated an exception: {exc}")
    return bad_parsing_findings


def main():
    script_start_time = time.time()
    init(autoreset=True)
    config = get_config_from_args()
    token = get_bearer_token(config)
    bad_parsing_findings = run_searches(config, token)
    if bad_parsing_findings:
        fieldnames = bad_parsing_findings[0].keys()
        with open("output.csv", "w", newline="") as output_file:
            csvwriter = csv.DictWriter(output_file, fieldnames=fieldnames)
            csvwriter.writeheader()
            csvwriter.writerows(bad_parsing_findings)
        print(f"{Fore.GREEN}Findings saved to output.csv")
    else:
        print(f"{Fore.GREEN}No bad parsing findings were identified.")

    print(
        f"{Fore.CYAN}Searches complete. Please also ensure to check the following for low count parsers - this may indicate misparsing."
    )
    print(
        f"{Fore.CYAN}https://{config['env_name']}{_get_region_url_specifier(config['region'])}.exabeam.cloud/app/search/query/results#z_H4sIAAAAAAAAE2WMTwuCMByGv8r4nSpc6DSC3cqkS2RNPdRFhi2R8k%2BbOwzxu4chInR9nud9O8i0lFctpAEKUXAK%2FBiVKk9b0wgL%2BWFyjherJeJqomlW66pFRxYmF7y%2FTRyF7BCwORnLXeSDBW1RCsarXADt4CnrEigQm2ywQzBxY2dLHZd69toj5D7k9cy79p%2F%2F6CJ7jX%2Fw5qrFW%2FzgRg1T0wzwV0DffwGfZgq84wAAAA%3D%3D"
    )
    script_end_time = time.time()
    print(
        f"\n{Fore.GREEN}Script finished in {script_end_time - script_start_time:.2f} seconds."
    )


if __name__ == "__main__":
    main()
