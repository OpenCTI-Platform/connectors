#!/usr/bin/env python3
import argparse
import logging
import os
import datetime
import json
import glob
import hashlib
import typing
from enum import Enum

import requests
import requests.adapters

__version__ = "1.0.0"


class FixedTimeoutAdapter(requests.adapters.HTTPAdapter):
    def send(self, *args, **kwargs):
        if kwargs["timeout"] is None:
            kwargs["timeout"] = 30
        return super(FixedTimeoutAdapter, self).send(*args, **kwargs)


class UnpacMeStatus(Enum):
    UNKNOWN = 0

    # Validating the uploaded file. The results list will not be populated at this point.
    VALIDATING = 1

    # The file has been queued for analysis. Depending on your account status analysis may be delayed during heavy
    # usage. The results list will not be populated at this point.
    QUEUED = 2

    # The file is being analyzed before the unpacking processor is selected. The results list will not be populated at
    # this point.
    ANALYZING = 3

    # The file has been analyzed and an unpacker selected. The file is now queued for unpacking. Depending on your
    # account status unpacking may be delayed during heavy usage. The results list will contain the analysis results
    # for the submitting file but it will not contain any unpacked files.
    UNPACK_PENDING = 4

    # The file is now being unpacked. The results list will contain the analysis results for the submitting file but it
    # will not contain any unpacked files.
    UNPACKING = 5

    # The file has been unpacked. The results list will contain the analysis results for the submitting file but it
    # will not contain any unpacked files.
    UNPACKED = 6

    # The file has been unpacked and the unpacked files have been submitted for analysis. The results list will contain
    # the analysis results for the submitting file and may begin to contain results for some of the unpacked files.
    POST_ANALYSIS = 7

    # The unpacking and analysis process has completed. The results list will contain the analysis results for the
    # submitting file and all unpacked files.
    COMPLETE = 8

    # The unpacking and analysis process has completed with errors. The results list may contain data but there is no
    # guarantee.
    FAIL = 9

    @staticmethod
    def from_string(status: str):
        if status == "validating":
            return UnpacMeStatus.VALIDATING
        elif status == "queued":
            return UnpacMeStatus.QUEUED
        elif status == "analyzing":
            return UnpacMeStatus.ANALYZING
        elif status == "unpack_pending":
            return UnpacMeStatus.UNPACK_PENDING
        elif status == "unpacking":
            return UnpacMeStatus.UNPACKING
        elif status == "unpacked":
            return UnpacMeStatus.UNPACKED
        elif status == "post_analysis":
            return UnpacMeStatus.POST_ANALYSIS
        elif status == "complete":
            return UnpacMeStatus.COMPLETE
        elif status == "fail":
            return UnpacMeStatus.FAIL


class Sha256:
    def __init__(self, sha256):
        if len(sha256) != 64:
            raise Exception(f'Invalid SHA256 hash: "{repr(sha256)}"')
        self.hash = sha256

    @staticmethod
    def from_data(data):
        return Sha256(hashlib.sha256(data).hexdigest())

    def __repr__(self):
        return f"<Sha256 {self.hash}>"

    def __eq__(self, other):
        return self.hash == other.hash


class UnpacMeUpload:
    def __init__(
        self,
        id,
        status: UnpacMeStatus,
        created: datetime.datetime,
        parent_sha256: typing.Optional[Sha256],
    ):
        self.id = id
        self.status = status
        self.created = created
        self.parent_sha256 = parent_sha256

    def __repr__(self):
        return f'<UnpacMeUpload {self.id} {self.status} {self.created.strftime("%Y-%m-%d %H:%M:%S")}>'


class UnpacMeQuota:
    def __init__(
        self,
        api_key: str,
        total_submissions: int,
        month_submissions: int,
        month_limit: int,
        roles: typing.List,
    ):
        self.api_key = api_key
        self.total_submissions = total_submissions
        self.month_submissions = month_submissions
        self.month_limit = month_limit
        self.roles = roles

    def __repr__(self):
        return (
            f"<UnpacMeQuota roles={self.roles} "
            f"total={self.total_submissions} month={self.month_submissions}/{self.month_limit}>"
        )


class UnpacMeUnpackedSample:
    def __init__(self, sha256: Sha256, malware_names: typing.List):
        self.sha256 = sha256
        self.malware_names = malware_names
        self.autoit_original_file_name = None
        self.autoit_sha256 = None

    def __repr__(self):
        return f"<UnpacMeUnpackedSample {self.sha256} {self.malware_names}>"

    @staticmethod
    def from_result(result):
        unpacked_sample = UnpacMeUnpackedSample(
            Sha256(
                result["hashes"]["sha256"]
                if "hashes" in result.keys()
                else result["sha256"]
            ),
            list(malware["name"] for malware in result["malware_id"])
            if "malware_id" in result.keys()
            else [],
        )
        if "autoit" in result.keys():
            unpacked_sample.autoit_original_file_name = result["autoit"][
                "metadata_original_name"
            ]
            unpacked_sample.autoit_sha256 = Sha256(result["autoit"]["sha256"])
        return unpacked_sample


class UnpacMeResults:
    def __init__(self, raw_json):
        self.raw_json = raw_json
        self.sha256 = Sha256(raw_json["sha256"])
        self.status = UnpacMeStatus.from_string(raw_json["status"])
        self.samples = [
            UnpacMeUnpackedSample.from_result(result) for result in raw_json["results"]
        ]

    def __repr__(self):
        return f"<UnpacMeResults status={self.status}>"


class FeedEntry:
    def __init__(
        self,
        upload: UnpacMeUpload,
        sha256: Sha256,
        malware_tags: typing.List[str],
        created: datetime.datetime,
        children: typing.List[Sha256],
        child_count: int = None,
    ):
        self.upload = upload
        self.sha256 = sha256
        self.malware_tags = malware_tags
        self.created = created
        self.children = children
        self.child_count = child_count

    def __repr__(self):
        return (
            f"<PublicFeedEntry "
            f'{self.created.strftime("%Y-%m-%d %H:%M:%S")} '
            f"{self.upload.id} {self.sha256.hash}>"
        )


class ApiException(Exception):
    pass


class UnpacMeApiException(ApiException):
    def __init__(self, error, description):
        self.error = error
        self.description = description


class HashNotFoundApiException(ApiException):
    pass


class UnpacMeApi:
    BASE_URL = "https://api.unpac.me/api/v1"

    def __init__(self, api_key, user_agent):
        self.session = requests.session()
        self.session.mount("https://", FixedTimeoutAdapter())
        self.session.mount("http://", FixedTimeoutAdapter())
        self.session.headers = {
            "User-Agent": user_agent,
            "Authorization": f"Key {api_key}",
        }

    def upload(self, data: bytes, private: bool) -> UnpacMeUpload:
        response = self.session.post(
            f"{self.BASE_URL}/private/upload",
            data={"private": private},
            files={"file": data},
        )
        if response.status_code != 200:
            raise ApiException(f"Api-Exception: {response.content}")
        return UnpacMeUpload(
            response.json()["id"],
            UnpacMeStatus.UNKNOWN,
            datetime.datetime.now(),
            Sha256.from_data(data),
        )

    def status(self, upload: UnpacMeUpload) -> UnpacMeStatus:
        response = self.session.get(f"{self.BASE_URL}/public/status/{upload.id}")
        if response.status_code != 200:
            raise ApiException(f"Api-Exception: {response.content}")
        return UnpacMeStatus.from_string(response.json()["status"])

    def results(self, upload: UnpacMeUpload) -> UnpacMeResults:
        response = self.session.get(f"{self.BASE_URL}/public/results/{upload.id}")
        if response.status_code != 200:
            raise ApiException(f"Api-Exception: {response.content}")
        return UnpacMeResults(response.json())

    def download(self, sha256: str) -> bytes:
        response = self.session.get(f"{self.BASE_URL}/private/download/{sha256}")
        if response.status_code != 200:
            raise ApiException(f"Api-Exception: {response.content}")
        return response.content

    def history(self) -> typing.Iterator[UnpacMeUpload]:
        cursor = None
        while True:
            response = self.session.get(
                f"{self.BASE_URL}/private/history",
                params={"cursor": cursor, "limit": 10},
            )
            if response.status_code == 404:
                break
            j = response.json()
            if response.status_code == 400:
                if "description" in j.keys() and "error" in j.keys():
                    raise UnpacMeApiException(j["error"], j["description"])

            yield from (
                UnpacMeUpload(
                    result["id"],
                    UnpacMeStatus.from_string(result["status"]),
                    datetime.datetime.utcfromtimestamp(result["created"]),
                    Sha256(result["sha256"]),
                )
                for result in j["results"]
            )
            cursor = j["cursor"]

    def search_hash(self, sha256: Sha256) -> typing.Iterator[FeedEntry]:
        response = self.session.get(
            f"{self.BASE_URL}/private/search/hash/{sha256.hash}"
        )
        j = response.json()
        if response.status_code == 404 and "description" in j.keys():
            raise HashNotFoundApiException(j["description"])

        for result in j["results"]:
            yield FeedEntry(
                UnpacMeUpload(
                    result["submission_id"],
                    UnpacMeStatus.from_string(result["status"]),
                    datetime.datetime.utcfromtimestamp(result["created"]),
                    Sha256(result["sha256"]),
                ),
                Sha256(result["sha256"]),
                [],
                datetime.datetime.utcfromtimestamp(result["created"]),
                [Sha256(sha256) for sha256 in result["children"]],
            )

    def get_quota(self) -> UnpacMeQuota:
        response = self.session.get(f"{self.BASE_URL}/private/user/access")
        j = response.json()
        if response.status_code != 200 and "error" in j.keys():
            raise ApiException(f"Api-Exception: {j}")

        return UnpacMeQuota(
            j["api_key"],
            j["total_submissions"],
            j["month_submissions"],
            j["month_limit"],
            j["roles"],
        )

    def public_feed(self) -> typing.Iterator[FeedEntry]:
        response = self.session.get(f"{self.BASE_URL}/public/feed")
        if response.status_code != 200:
            raise ApiException(f"Api-Exception: {response.content}")

        j = response.json()
        for result in j["results"]:
            yield FeedEntry(
                UnpacMeUpload(
                    result["id"],
                    UnpacMeStatus.from_string(result["status"]),
                    datetime.datetime.utcfromtimestamp(result["created"]),
                    result["sha256"],
                ),
                Sha256(result["sha256"]),
                [malware["match"] for malware in result["malwareid"]],
                datetime.datetime.utcfromtimestamp(result["created"]),
                [Sha256(sha256) for sha256 in result["children"]]
                if isinstance(result["children"], list)
                else [],
                result["children"],
            )


class ConsoleHandler(logging.Handler):
    def emit(self, record):
        print("[%s] %s" % (record.levelname, record.msg))


if __name__ == "__main__":
    import platform
    import time

    QUOTA_WARN_PERCENTAGE = 0.2

    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command")

    quota_parser = subparsers.add_parser("quota", help="Print current quota stats.")

    search_parser = subparsers.add_parser("search", help="Searches SHA256 hash.")
    search_parser.add_argument("sha256")

    download_parser = subparsers.add_parser(
        "download", help="Download file by SHA256 hash."
    )
    download_parser.add_argument("sha256")
    download_parser.add_argument(
        "--file-name",
        help="Specify file name, will use SHA256 as file name if not specified",
    )

    feed_parser = subparsers.add_parser(
        "feed",
        help="Returns a list of analysis entries for recently submitted samples. This is for demonstration purposes "
        "only.",
    )
    feed_parser.add_argument(
        "--children-only", action="store_true", help="Only list those with children"
    )
    feed_parser.add_argument(
        "--completed-only",
        action="store_true",
        help="Only list those that are completed",
    )
    feed_parser.add_argument(
        "--malware-only",
        action="store_true",
        help="Only list those that have a malware assigned",
    )
    feed_parser.add_argument(
        "--sha256", action="store_true", help="Only print SHA256 hashes"
    )

    history_parser = subparsers.add_parser(
        "history", help="Request a list of your past submissions."
    )

    status_parser = subparsers.add_parser(
        "status", help="Check status for given upload ID."
    )
    status_parser.add_argument("upload_id", help="ID acquired by uploading a file")
    status_parser.add_argument(
        "-l", "--list", action="store_true", help="List details of task."
    )
    status_parser.add_argument(
        "-d",
        "--details",
        action="store_true",
        help="Collect details of run in case job is completed.",
    )
    status_parser.add_argument("-u", "--download-unpacked-files", action="store_true")

    upload_parser = subparsers.add_parser(
        "upload", help="Upload a PE file for unpacking and analysis."
    )
    upload_parser.add_argument("file_names", nargs="+", help="Files to be uploaded")
    upload_parser.add_argument(
        "-f", "--force", help="Force upload, even if hash already exists."
    )
    upload_parser.add_argument(
        "--print-id",
        action="store_true",
        help="Do not poll for results but print upload ID and terminate.",
    )
    upload_parser.add_argument(
        "--poll-interval", default=20, help="Number of seconds between polls."
    )

    parser.add_argument(
        "--api-key",
        default=os.getenv("UNPACME_API_KEY", None),
        help="Get your API key from https://www.unpac.me/account",
    )
    parser.add_argument("--debug", action="store_true")
    parser.add_argument(
        "--user-agent",
        default=f"UnpacMeClient/{__version__} (python-requests {requests.__version__}) "
        f"{platform.system()} ({platform.release()})",
    )
    parser.add_argument(
        "--ignore-quota",
        action="store_true",
        help="Client tries to regularly check your quota to print warnings accordingly. "
        "Pass this switch to disable this behavior",
    )
    args = parser.parse_args()

    logger = logging.getLogger("UnpacMeClient")
    logger.handlers.append(ConsoleHandler())
    logger.setLevel(logging.DEBUG if args.debug else logging.INFO)

    logger.debug(f"Using User-Agent string: {args.user_agent}")
    api = UnpacMeApi(args.api_key, args.user_agent)
    try:
        if args.command == "upload":
            tasks = []
            for pattern in args.file_names:
                for file_name in glob.glob(pattern):
                    logger.debug(f'Tasking "{file_name}"...')
                    if not os.path.exists(file_name):
                        logger.error(f'Path "{file_name}" does not exist.')
                        continue
                    if not os.path.isfile(file_name):
                        logger.error(f'Path "{file_name}" is not a file.')
                        continue
                    with open(file_name, "rb") as fp:
                        file_data = fp.read()

                    try:
                        next(api.search_hash(Sha256.from_data(file_data)))
                        logger.error(f'Hash of "{file_name}" already exists, skipping.')
                        hash_already_uploaded = True
                    except HashNotFoundApiException:
                        hash_already_uploaded = False
                    if hash_already_uploaded:
                        continue

                    tasks.append(file_data)

            if not args.force:
                quota = api.get_quota()
                remaining = quota.month_limit - quota.month_submissions
                percentage = float(len(tasks)) / float(remaining)
                if percentage > QUOTA_WARN_PERCENTAGE:
                    logger.error(
                        f"This operation would use up {percentage:.0%} of your remaining quota, pass -f to execute it "
                        f"anyway"
                    )
                    exit()

            for file_data in tasks:
                upload = api.upload(file_data)
                if args.print_id:
                    print(f"Your upload ID: {upload.id}")
                    continue

                while True:
                    logger.debug(f'polling status of submission id "{upload.id}"...')
                    status = api.status(upload)
                    if status == UnpacMeStatus.COMPLETE:
                        break
                    time.sleep(args.poll_interval)
                logger.info(f"Unpacking finished: {api.results(upload)}")

        elif args.command == "quota":
            quota = api.get_quota()
            logger.debug(f"Quota: {quota}")
            percentage = float(quota.month_submissions) / float(quota.month_limit)
            print(
                f"You already used {percentage:.0%} "
                f"({quota.month_submissions} / {quota.month_limit}) of your quota this month."
            )

        elif args.command == "status":
            upload = UnpacMeUpload(
                args.upload_id, UnpacMeStatus.UNKNOWN, datetime.datetime.now(), None
            )
            status = api.status(upload)
            if status == UnpacMeStatus.COMPLETE:
                logger.info("Task completed")
                results = (
                    api.results(upload)
                    if (args.details or args.download_unpacked_files or args.list)
                    else None
                )
                if args.details:
                    print(json.dumps(results.raw_json, indent=4))
                if args.list:
                    print(f"SHA256: {results.sha256.hash}")
                    print("")
                    print("Unpacked Files")
                    print("---")
                    for sample in results.samples:
                        line = f"{sample.sha256.hash}"
                        if sample.malware_names:
                            line += f' ({", ".join(sample.malware_names)})'
                        if sample.autoit_sha256:
                            line += f" [{sample.autoit_original_file_name}, {sample.autoit_sha256.hash}]"
                        print(line)
                if args.download_unpacked_files:

                    def download_to_file(sha256: Sha256, file_name: str):
                        if os.path.exists(file_name):
                            logger.warning(
                                f'Skipping "{file_name}" because file already exists'
                            )
                            return
                        logger.debug(f'Downloading "{file_name}"...')
                        with open(file_name, "wb") as fp:
                            fp.write(api.download(sha256))

                    original_sha256 = results.sha256
                    for sample in results.samples:
                        if sample.autoit_sha256:
                            download_to_file(
                                sample.autoit_sha256,
                                f"{original_sha256.hash}.{sample.sha256.hash}._au3",
                            )
                        if sample.sha256 != original_sha256:
                            download_to_file(
                                sample.sha256,
                                f"{original_sha256.hash}.{sample.sha256.hash}._exe",
                            )
            else:
                logger.info("Task not completed")

        elif args.command == "history":
            for upload in api.history():
                print(
                    f'{upload.created.strftime("%Y-%m-%d %H:%M:%S")} '
                    f"{upload.id} {upload.parent_sha256.hash} "
                    f"({upload.status})"
                )

        elif args.command == "download":
            sha256 = Sha256(args.sha256.strip())
            file_name = sha256.hash if args.file_name is None else args.file_name
            if os.path.exists(file_name):
                logger.warning(f'Skipping "{file_name}" because it already exists.')
                exit()

            logger.debug(f'Downloading "{file_name}"...')
            with open(file_name, "wb") as fp:
                fp.write(api.download(sha256))

        elif args.command == "search":
            sha256 = Sha256(args.sha256.strip())
            for entry in api.search_hash(sha256):
                print(f"SHA256: {entry.sha256.hash}")
                print(f"Submission-ID: {entry.upload.id}")
                print(f'Created at: {entry.created.strftime("%Y-%m-%d %H:%M:%S")}')
                print("")
                print("Unpacked Files")
                for child in entry.children:
                    print(child.hash)

        elif args.command == "feed":
            for entry in api.public_feed():
                if args.children_only and entry.children == 0:
                    continue
                if (
                    args.completed_only
                    and entry.upload.status != UnpacMeStatus.COMPLETE
                ):
                    continue
                if args.malware_only and len(entry.malware_tags) == 0:
                    continue

                if args.sha256:
                    print(entry.sha256.hash)
                else:
                    print(
                        f'{entry.created.strftime("%Y-%m-%d %H:%M:%S")}: {entry.upload.id} '
                        f'({entry.sha256.hash}) {", ".join(entry.malware_tags)}'
                    )

    except ApiException as e:
        logger.exception(e)
