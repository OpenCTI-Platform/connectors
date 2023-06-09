# Copyright (C) 2020-2023 Hatching B.V
# All rights reserved.

from io import BytesIO
from triage.pagination import Paginator
from .__version__ import __version__
from requests import Request, Session, exceptions, utils

import binascii
import urllib3
import json
import os
import platform

urllib3.disable_warnings()

class Client:
    def __init__(self, token, root_url='https://api.tria.ge'):
        self.token = token
        self.root_url = root_url.rstrip('/')

    def _new_request(self, method, path, j=None, b=None, headers=None):
        if headers is None:
            headers = {}

        headers = {
            "Authorization": f"Bearer {self.token}",
            "User-Agent": f"Python/{platform.python_version()} "
                          f"Triage Python Client/{__version__}",
            **headers
        }
        if j:
            return Request(method, self.root_url + path, data=json.dumps(j), headers=headers)
        return Request(method, self.root_url + path, data=b, headers=headers)

    def _req_file(self, method, path):
        r = self._new_request(method, path)
        with Session() as s:
            settings = s.merge_environment_settings(r.url, {}, None, False, None)
            return s.send(r.prepare(), **settings).content

    def _req_json(self, method, path, data=None):
        if data is None:
            r = self._new_request(method, path, data)
        else:
            r = self._new_request(method, path, data,
                headers={'Content-Type': 'application/json'})

        try:
            with Session() as s:
                settings = s.merge_environment_settings(r.url, {}, None, False, None)
                res = s.send(r.prepare(), **settings)
                res.raise_for_status()
                return res.json()
        except exceptions.HTTPError as err:
            raise ServerError(err)

    def submit_sample_file(self, filename, file, interactive=False, profiles=None, password=None, timeout=150, network="internet"):
        """
        Submit a file for analysis on Triage.

        Parameters:
            filename (str):
                The name of the file
            file (file):
                Object with a read method (e.g. open("file.exe", "r"))
            interactive (bool):
                Whether to select files for analysis; defaults to False
            profiles (list):
                Select a profile for every individiual target
                [
                    {
                        "pick": "file1.exe", // for archives
                        "profile": "w7_long"
                    }
                ]
            password (str):
                Password for the archive sample
            timeout: (int):
                Timeout of the analysis
            network (str):
                Type of network routing to use ("internet" | "drop" | "tor" | "sim200" | "sim404" | "simnx")
        Returns:
            response (dict):
                {
                    'id': '200923-4zhlr84m42',
                    'status': 'pending',
                    'kind': 'file',
                    'filename': 'test.exe',
                    'private': False,
                    'submitted': '2020-09-23T07:26:26Z'
                }
        """
        if profiles is None:
            profiles = []
        d = {
            'kind': 'file',
            'interactive': interactive,
            'profiles': profiles,
            'defaults': {
                'timeout': timeout,
                'network': network
            }
        }
        if password:
            d['password'] = password
        body, content_type = encode_multipart_formdata({
            '_json': json.dumps(d),
            'file': (filename, file),
        })
        r = self._new_request('POST', '/v0/samples', b=body,
            headers={"Content-Type": content_type}
        )
        try:
            with Session() as s:
                settings = s.merge_environment_settings(r.url, {}, None, False, None)
                res = s.send(r.prepare(), **settings)
                res.raise_for_status()
                return res.json()
        except exceptions.HTTPError as err:
            raise ServerError(err)

    def submit_sample_url(self, url, interactive=False, profiles=None):
        """
        Submit a url for analysis on Triage.

        Parameters:
            url (str): The url to analyse
            interactive (bool):
                Whether to select files for analysis; defaults to False
            profiles (list):
                Select a profile for every individual target
                [
                    {
                        "profile": "w7_long"
                    }
                ]
        Returns:
            response (dict):
                {
                    'id': '200923-esktrbc2a6',
                    'status': 'pending',
                    'kind': 'url',
                    'url': 'http://www.google.com',
                    'private': False,
                    'submitted': '2020-09-23T07:51:45Z'
                }
        """
        if profiles is None:
            profiles = []
        return self._req_json('POST', '/v0/samples', {
            'kind': 'url',
            'url': url,
            'interactive': interactive,
            'profiles': profiles,
        })

    def set_sample_profile(self, sample_id, profiles):
        """
        Set profile for a sample, if the sample has been submitted in
        interactive mode.

        Parameters:
            sample_id (str): The id of the sample
            profiles (list):
                Select a profile for every individiual target
                [
                    {
                        "pick": "file.exe", // for archives
                        "profile": "w7_long"
                    }
                ]
        Returns:
            response (dict):
                {}, empty dict
        """
        return self._req_json('POST', '/v0/samples/%s/profile' % sample_id, {
            'auto': False,
            'profiles': profiles,
        })

    def set_sample_profile_automatically(self, sample_id, pick=None):
        """
        Set profile for a sample automatically, if the sample has been
        submitted in interactive mode.

        Parameters:
            sample_id (str): The id of the sample
            pick (list):
                [
                    "file1.exe",
                    "file2.exe"
                ]

        Returns:
            response (dict):
                {}, empty dict
        """
        if pick is None:
            pick = []
        return self._req_json('POST', '/v0/samples/%s/profile' % sample_id, {
            'auto': True,
            'pick': pick,
        })

    def org_samples(self, max=20):
        """
        Returns a Paginator object with organisation samples.

        Parameters:
            max (int): The maximum amount of samples to return

        Returns:
            Paginator (object):
                Loop over this object to get the samples
        """
        return Paginator(self, '/v0/samples?subset=org', max)

    def owned_samples(self, max=20):
        """
        Returns a Paginator object with owned samples.

        Parameters:
            max (int): The maximum amount of samples to return

        Returns:
            Paginator (object):
                Loop over this object to get the samples
        """
        return Paginator(self, '/v0/samples?subset=owned', max)

    def public_samples(self, max=20):
        """
        Returns a Paginator object with public samples.

        Parameters:
            max (int): The maximum amount of samples to return

        Returns:
            Paginator (object):
                Loop over this object to get the samples
        """
        return Paginator(self, '/v0/samples?subset=public', max)

    def sample_by_id(self, sample_id):
        """
        Returns a sample object.

        Parameters:
            sample_id (str): The id of the sample

        Returns:
            Sample (object):
                {
                    'id': '200923-hb5gvebega',
                    'status': 'static_analysis',
                    'kind': 'url',
                    'url': 'http://google.com',
                    'private': False,
                    'tasks': [
                        {
                            'id': 'static1',
                            'status': 'reported'
                        }
                    ],
                    'submitted': '2020-09-23T08:04:58Z'
                }
        """
        return self._req_json('GET', '/v0/samples/{0}'.format(sample_id))

    def get_sample_file(self, sample_id):
        """
        Return the sample file.

        Parameters:
            sample_id (str): The id of the sample

        Returns:
            response (file):
                File object.
        """
        return self._req_file("GET", "/v0/samples/{0}/sample".format(sample_id))

    def delete_sample(self, sample_id):
        """
        Delete a sample.

        Parameters:
            sample_id (str): The id of the sample

        Returns:
            response (dict):
                {}, empty dict
        """
        return self._req_json('DELETE', '/v0/samples/{0}'.format(sample_id))

    def search(self, query, max=20):
        """
        Returns a Paginator object with search samples.

        Parameters:
            query (str): The search query
            max (int): The maximum amount of samples to return

        Returns:
            Paginator (object):
                Loop over this object to get the samples
        """
        params = utils.quote(query)
        return Paginator(self, '/v0/search?query={0}'.format(params), max)

    def static_report(self, sample_id):
        """
        Return a static report.

        Parameters:
            sample_id (str): The id of the sample

        Returns:
            response (dict):
                {
                    'version': '0.2',
                    'sample': {},
                    'task': {},
                    'analysis': {},
                    'files': None,
                    'unpack_count': 0,
                    'error_count': 0
                }
        """
        return self._req_json(
            'GET', '/v0/samples/{0}/reports/static'.format(sample_id)
        )

    def overview_report(self, sample_id):
        """
        Return an overivew of the sample.

        Parameters:
            sample_id (str): The id of the sample

        Returns:
            response (dict):
                {
                    'version': '0.2.2',
                    'sample': {},
                    'task': {},
                    'analysis': {},
                    'targets': {},
                    'extracted': {},
                    'errors': {} (omitted when empty)
                }
        """
        return self._req_json(
            'GET', '/v1/samples/{0}/overview.json'.format(sample_id)
        )

    def kernel_report(self, sample_id, task_id):
        """
        Return kernel output.

        Parameters:
            sample_id (str): The id of the sample
            task_id (str): The id of the task

        Returns:
            List of json entries
            [
                {"kind": ".."},
                {"kind": ".."},
                {"kind": ".."},
            ]
        """
        overview = self.overview_report(sample_id)
        for t in overview.get("tasks", []):
            if t.get("name") == task_id:
                task = t
                break
        else:
            raise ValueError("Task does not exist")

        log_file = None
        platform = task.get("platform") or task.get("os")
        if "windows" in platform:
            log_file = "onemon"
        elif "linux" in platform or "ubuntu" in platform:
            log_file = "stahp"
        elif "macos" in platform:
            log_file = "bigmac"
        elif "android" in platform:
            log_file = "droidy"
        else:
            raise ValueError("Platform not supported")

        r = self._new_request(
            'GET', '/v0/samples/{0}/{1}/logs/{2}.json'.format(
                sample_id, task_id, log_file)
        )

        with Session() as s:
            settings = s.merge_environment_settings(r.url, {}, None, False, None)
            res = s.send(r.prepare(), **settings)
            res.raise_for_status()
            for entry in res.content.split(b"\n"):
                if entry.strip() == b"":
                    break
                yield json.loads(entry)

    def task_report(self, sample_id, task_id):
        """
        Return a task report.

        Parameters:
            sample_id (str): The id of the sample
            task_id (str): The id of the task

        Returns:
            response (dict):
                {
                    'version': '0.2.2',
                    'sample': {},
                    'task': {},
                    'errors': [],
                    'analysis': {},
                    'signatures': [],
                    'network': {}
                }
        """
        return self._req_json(
            'GET', '/v0/samples/{0}/{1}/report_triage.json'.format(
                sample_id, task_id)
        )

    def sample_task_file(self, sample_id, task_id, filename):
        """
        Return a task file.

        Parameters:
            sample_id (str): The id of the sample
            task_id (str): The id of the task
            filename (str): The name of the file

        Returns:
            response (file):
                File object.
        """
        return self._req_file(
            "GET", "/v0/samples/{0}/{1}/{2}".format(
                sample_id, task_id, filename)
        )

    def sample_archive_tar(self, sample_id):
        """
        Return a tar achive of a sample.

        Parameters:
            sample_id (str): The id of the sample

        Returns:
            response (file):
                File object.
        """
        return self._req_file(
            "GET", "/v0/samples/{0}/archive".format(sample_id)
        )

    def sample_archive_zip(self, sample_id):
        """
        Return a zip achive of a sample.

        Parameters:
            sample_id (str): The id of the sample

        Returns:
            response (file):
                File object.
        """
        return self._req_file(
            "GET", "/v0/samples/{0}/archive.zip".format(sample_id)
        )

    def create_profile(self, name, tags, network, timeout):
        """
        Create a new profile.

        Parameters:
            name (str): The name of the profile
            tags (list): Tags for the profile, list of strings
            network (str): network used when running the sample (Currently available : "", "drop", "internet")
            timeout (int): The timeout of the profile

        Returns:
            response (dict):
                {}, empty dict
        """
        return self._req_json("POST", "/v0/profiles", data={
            "name": name,
            "tags": tags,
            "network": network,
            "timeout": timeout
        })

    def delete_profile(self, profile_id):
        """
        Delete profile.

        Parameters:
            profile_id (str): The name or id of the profile

        Returns:
            response (dict):
                {}, empty dict
        """
        return self._req_json('DELETE', '/v0/profiles/{0}'.format(profile_id))

    def profiles(self, max=20):
        """
        Returns a Paginator object with profiles.

        Parameters:
            max (int): The maximum amount of profiles to return

        Returns:
            Paginator (object):
                Loop over this object to get the profiles
        """
        return Paginator(self, '/v0/profiles', max)

    def sample_events(self, sample_id):
        """
        Stream events of a running sample.

        Parameters:
            sample_id (str): The id of the sample

        Returns:
            yield of dict events
        """
        events = self._new_request("GET", "/v0/samples/"+sample_id+"/events")
        with Session() as s:
            settings = s.merge_environment_settings(events.url, {}, None, False, None)
            if 'stream' in settings:
                del settings['stream']
            res = s.send(events.prepare(), stream=True, **settings)
            for line in res.iter_lines():
                if line:
                    yield json.loads(line)

def PrivateClient(token):
    return Client(token, "https://private.tria.ge/api")

class ServerError(Exception):
    def __init__(self, err):
        try:
            b = err.response.json()
        except json.JSONDecodeError:
            b = {}

        self.status = err.response.status_code
        self.kind = b.get("error", "")
        self.message = b.get("message", "")

    def __str__(self):
        return 'triage: {0} {1}: {2}'.format(
            self.status, self.kind, self.message)


def encode_multipart_formdata(fields):
    boundary = binascii.hexlify(os.urandom(16)).decode('ascii')

    body = BytesIO()
    for field, value in fields.items(): # (name, file)
        if isinstance(value, tuple):
            filename, file = value
            body.write('--{boundary}\r\nContent-Disposition: form-data; '
                       'filename="{filename}"; name=\"{field}\"\r\n\r\n'
                .format(boundary=boundary, field=field, filename=filename)
                .encode('utf-8'))
            b = file.read()
            if isinstance(b, str):  # If the file was opened in text mode
                b = b.encode('ascii')
            body.write(b)
            body.write(b'\r\n')
        else:
            body.write('--{boundary}\r\nContent-Disposition: form-data;'
                       'name="{field}"\r\n\r\n{value}\r\n'
                .format(boundary=boundary, field=field, value=value)
                .encode('utf-8'))
    body.write('--{0}--\r\n'.format(boundary).encode('utf-8'))
    body.seek(0)

    return body, "multipart/form-data; boundary=" + boundary
