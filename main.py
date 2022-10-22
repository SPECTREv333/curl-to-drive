from __future__ import print_function

import json
import os
import os.path
import argparse

import requests
import urllib3
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow


def curl_to_requests(curl_command):
    # translate curl command to arguments for python requests
    curl_command = curl_command.split("-H")
    url = curl_command[0].split("'")[1]
    headers = {}
    data = None
    for i in range(2, len(curl_command)):
        curl_command[i] = curl_command[i].split("'")
        headers[curl_command[i][1].split(":")[0]] = curl_command[i][1].split(": ")[1]
    return url, headers


def request_factory(url, headers=None):
    r = requests.get(url, headers=headers, stream=True)
    r.raise_for_status()
    if "Content-Disposition" in r.headers.keys() is not None:
        local_filename = r.headers["Content-Disposition"].split("=")[1].strip('"')
    else:
        local_filename = "untitled"
    return r, local_filename


# If modifying these scopes, delete the file token.json.
SCOPES = ['https://www.googleapis.com/auth/drive']


def get_cred():
    creds = None
    # The file token.json stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first
    # time.
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        # Save the credentials for the next run
        with open('token.json', 'w') as token:
            token.write(creds.to_json())
    return creds


def get_input():
    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('curl_command', metavar='command', type=str,
                        help='Command to be translated')
    return parser.parse_args().curl_command


def main():
    curl_command = get_input()
    url, pars_headers = curl_to_requests(curl_command)
    req, filename = request_factory(url, headers=pars_headers)

    if (cred := get_cred()) is not None:
        access_token = cred.token
    else:
        print("unable to get cred")
        exit(1)

    gapihead = {"Authorization": "Bearer " + access_token, "Content-Type": "application/json"}
    params = {
        "name": filename,
        "mimeType": "video/mp4"
    }

    r = requests.post(
        "https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable",
        headers=gapihead,
        data=json.dumps(params)
    )

    #print(r.headers)
    location = r.headers['Location']

    chunk_size = 262144 #minimum required
    filesize = int(req.headers["Content-Length"])
    tests = 0

    raw_resp: urllib3.HTTPResponse = req.raw

    for chunk in raw_resp.stream(chunk_size, decode_content=False):
        # If you have chunk encoded response uncomment if
        # and set chunk_size parameter to None.
        # if chunk:
        #range_end = x if (x := tests + len(chunk)) == filesize else (x-1)
        range_end = tests + len(chunk) - 1
        headers = {
            "Content-Length": str(len(chunk)),
            "Content-Range": f"bytes {tests}-{range_end}/{filesize}"
        }
        print(f"uploaded range: {tests}-{range_end} filesize: {filesize} progress: {(range_end+1/filesize*100)}%")
        tests += len(chunk)
        r = requests.put(
            location,
            headers=headers,
            data=chunk
        )
        print(f"{r.status_code}: {r.text}")

    r.close()
    req.close()


if __name__ == '__main__':
    main()
