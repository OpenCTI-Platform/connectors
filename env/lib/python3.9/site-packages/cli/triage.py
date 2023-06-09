# Copyright (C) 2020-2022 Hatching B.V.
# All rights reserved.

import sys
import os
import time
import json

import click
import appdirs

from triage import Client
from triage.client import ServerError
from cli.tui import prompt_select_options

def token_file():
    return os.path.join(appdirs.user_config_dir(), "triage.conf")

def client_from_env():
    tokenfile = token_file()
    if not os.path.exists(tokenfile):
        print("Please authenticate")
        sys.exit()
        return

    with open(token_file(), "r") as f:
        for line in f:
            line = line.strip()
            if len(line) == 0 or line.startswith("#"):
                continue

            url, token = line.split(" ")
            return Client(token, root_url=url)

    print("%s is not formatted correctly" % tokenfile)
    sys.exit()

@click.group()
def cli():
    pass

@cli.command()
@click.argument("token")
@click.option("-u", "--url", default="https://api.tria.ge", show_default=True,
              help="The endpoint of your triage instance")
def authenticate(token, url):
    tokenfile = token_file()
    if os.path.exists(tokenfile):
        print("Tokenfile already exists, currently appending tokens is not "
            "supported, please edit/remove: ", tokenfile)
        return

    with open(token_file(), "w") as f:
        f.write("%s %s" % (url, token))

def prompt_select_files(static):
    print("Please select the files from the archive to analyze/")
    print("Leave blank to continue with the emphasized files and automatic "
        "profiles.")

    selection = prompt_select_options(static["files"], key="filename")
    if len(selection) == 0:
        return [{
                "name": x["filename"],
                "path": x.get("relpath")
            } for x in static["files"] if x["selected"]], True
    return [{
            "name": static["files"][i]["filename"],
            "path": static["files"][i].get("relpath")
        } for i in selection], False

def prompt_select_profiles_for_files(profiles, pick):
    f = None
    if len(pick) > 1:
        f = lambda x : len(x) > 0

    rt = []
    for i in pick:
        print("Please select the profiles to use for", i["name"])
        selection = prompt_select_options(
            profiles,
            key="name",
            f=f
        )
        for choice in selection:
            rt.append({
                "profile": profiles[choice]["id"],
                "pick": i["path"]
            })
    return rt

def prompt_select_profile(c, sample):
    for events in c.sample_events(sample):
        if events["status"] == "pending":
            print("waiting for static analysis to finish")
        elif events["status"] == "static_analysis":
            break
        elif events["status"] == "failed":
            print("the sample is in a failed state")
            return
        else:
            print("the sample does not need a profile to be selected")
            return
    static = c.static_report(sample)
    pick = []
    default_selection = False
    if static["sample"]["kind"] == "url":
        pick.append({
            "name": static["sample"]["target"],
            "path": static["sample"]["target"]
        })
    elif len(static["files"]) == 1:
        pick.append({
            "name": static["files"][0]["filename"],
            "path": static["files"][0].get("relpath"),
        })
    else:
        pick, default_selection = prompt_select_files(static)

    # Fetch profiles before determining whether we should use automatic
    #  profiles. If no profiles are available, fall back to automatic profiles.
    profiles = [x for x in c.profiles()]
    default_selection = (len(profiles) == 0)

    profile_selections = []
    if not default_selection:
        profile_selections = prompt_select_profiles_for_files(profiles, pick)
        default_selection = (len(profile_selections) == 0)

    if default_selection:
        print("Using default selection.")
        c.set_sample_profile_automatically(
            sample,
            pick=[i["path"] for i in pick]
        )
        return

    c.set_sample_profile(sample, profile_selections)

@cli.command("submit")
@click.argument("target")
@click.option("-i", "--interactive", is_flag=True, help="Perform interactive"
" submission where you can manually select the profile and files")
@click.option("-p", "--profile", multiple=True, help="The profile names or IDs"
" to use")
def submit(target, interactive, profile):
    f, url = None, None
    if os.path.exists(target):
        f = target
    else:
        url = target

    if interactive and profile:
        print("--interactive and --profile are mutually exclusive")
        return

    c = client_from_env()
    if f:
        name = os.path.basename(f)
        r = c.submit_sample_file(
            name, open(f, "rb"),
            interactive=interactive,
            profiles=[{
                "profile": x
            } for x in profile]
        )
    elif url:
        r = c.submit_sample_url(
            url, interactive=interactive,
            profiles=[{
                "profile": x
            } for x in profile]
        )
    else:
        print("Please specify -f file or -u url")
        return

    print("Sample submitted")
    print("  ID:       %s" % r.get("id"))
    print("  Status:   %s" % r.get("status"))
    if f:
        print("  Filename: %s" % r.get("filename"))
    else:
        print("  URL:      %s" % r.get("url"))

    if interactive:
        time.sleep(2)
        prompt_select_profile(c, r.get("id"))

@cli.command("select-profile")
@click.argument("sample")
def select_profile(sample):
    c = client_from_env()
    prompt_select_profile(c, sample)

def paginator_format(c, i):
    target = i.get("url") if i.get("url") else i.get("filename", "-")
    if i.get("status") == "reported":
        try:
            overview = c.overview_report(i["id"])
        except ServerError:
            return
        if len(overview.get("analysis", {}).get("family", [])) >= 1:
            print("%s\t%s, %s\t%s" % (
                overview.get("analysis", {}).get("score", "N/A"),
                i.get("id"),
                overview.get("analysis", {}).get("family"),
                target
            ))
        else:
            print("%s\t%s\t%s" % (
                overview.get("analysis", {}).get("score", "N/A"),
                i.get("id"),
                target
            ))
    else:
        print(".\t%s\t%s" % (
            i.get("id"),
            target
        ))

@cli.command("list")
@click.option("-n", default=20, show_default=True,
              help="The maximum number of samples to return")
@click.option("-p", "--public", is_flag=True, help="List public samples")
def list_samples(public, n):
    c = client_from_env()
    for i in c.public_samples(max=n) if public else c.owned_samples(max=n):
        paginator_format(c, i)

@cli.command("file")
@click.argument("sample")
@click.argument("task")
@click.argument("file")
@click.option("-o", "--output", help= "The path to where the "
    "downloaded file should be saved. If `-`, the file is copied to stdout")
def get_file(sample, task, file, output):
    c = client_from_env()
    f = c.sample_task_file(sample, task, file)
    if output == "-":
        print(f)
    if not output:
        output = "".join(x for x in file if x not in "\/:*?<>|")
    with open(output, "wb") as wf:
        wf.write(f)

@cli.command("archive")
@click.argument("sample")
@click.option("-f", "--format", default="tar", show_default=True,
    help="The archive format. Either \"tar\" or \"zip\"")
@click.option("-o", "--output", help="The target file name. If `-`, the file "
"is copied to stdout. Defaults to the sample ID with appropriate extension")
def archive(sample, format, output):
    c = client_from_env()
    if format == "tar":
        r = c.sample_archive_tar(sample)
    elif format == "zip":
        r = c.sample_archive_zip(sample)
    else:
        print("Use --format zip or tar")
        return

    if output == "-":
        print(r)
    elif output:
        with open(output, "wb") as wf:
            wf.write(r)
    else:
        with open("%s.%s" % (sample, format), "wb") as wf:
            wf.write(r)


@cli.command("delete")
@click.argument("sample")
def delete(sample):
    c = client_from_env()
    c.delete_sample(sample)

@cli.command("onemon.json")
@click.argument("sample")
@click.argument("tasks", nargs=-1)
def onemon(sample, tasks):
    c = client_from_env()
    for k in c.overview_report(sample).get("tasks", []):
        if k.get("kind") == "behavioral":
            if tasks and k.get("name") not in tasks:
                continue
            for line in c.kernel_report(sample, k.get("name")):
                print(json.dumps(line, separators=(',', ':')))

@cli.command("search", help="Use https://tria.ge/docs/cloud-api/samples/#get-search for query formats")
@click.argument("query")
@click.option("-n", default=20, show_default=True,
              help="The maximum number of samples to return")
def search(query, n):
    c = client_from_env()
    for i in c.search(query, n):
        paginator_format(c, i)

@cli.command("report")
@click.argument("sample")
@click.option("--static", is_flag=True, help="Query the static report")
@click.option("-t", "--task", help="The ID of the report")
def report(sample, static, task):
    c = client_from_env()
    if static:
        print("~Static Report~")
        r = c.static_report(sample)
        for f in r.get("files", []):
            print("%s %s" % (
                f.get("filename"),
                "(selected)" if f.get("selected") else "")
            )
            print("  md5:", f.get("md5"))
            print("  tags:", f.get("tags", []))
            print("  kind:", f.get("kind"))
    elif task:
        print("~%s Report~" % task)
        r = c.task_report(sample, task)
        err = r.get("errors")
        if err:
            print(err)
            return

        print(r.get("task", {}).get("target"))
        print("  md5:", r.get("task", {}).get("md5"))
        print("  score:", r.get("analysis", {}).get("score"))
        print("  tags:", r.get("analysis", {}).get("tags", []))
    else:
        print("~Overview~")
        r = c.overview_report(sample)
        if r.get("errors"):
            print("Triage produced the following errors", r["errors"])
        print(r.get("sample", {}).get("target"))
        print("  md5:", r.get("sample", {}).get("md5"))
        print("  score:", r.get("analysis", {}).get("score"))
        print("  family:", r.get("analysis", {}).get("family"))
        print("  tags:", r.get("analysis", {}).get("tags", []))
        print()
        for task in r.get("tasks", []):
            print(" ", task.get("name"))
            print("    score:", task.get("score", "N/A"))
            if task.get("kind") != "static":
                print("    platform:", task.get("platform") or task.get("os"))
            print("    tags:", task.get("tags", []))

@cli.command("create-profile")
@click.option("--name", required=True, help="The name of the new profile")
@click.option("--tags", required=True, help="A comma separated set of tags")
@click.option("--network", help="The network type to use. Either \"internet\","
    " \"drop\" or unset")
@click.option("--timeout", required=True, type=int,
    help="The timeout of the profile")
def create_profile(name, tags, network, timeout):
    c = client_from_env()
    r = c.create_profile(name, tags.split(","), network, timeout)
    print(r)

@cli.command("delete-profile")
@click.option("-p", "--profile", required=True,
    help="The name or ID of the profile")
def delete_profile(profile):
    c = client_from_env()
    r = c.delete_profile(profile)
    print(r)

@cli.command("list-profiles")
@click.option("-n", default=20, show_default=True,
              help="The maximum number of profiles to return")
def list_profiles(n):
    c = client_from_env()
    for i in c.profiles(max=n):
        print(i.get("name"))
        print("  timeout:", i.get("timeout"))
        print("  network:", i.get("network"))
        print("  tags:", i.get("tags", []))
        print("  id:", i.get("id"))

if __name__ == "__main__":
    cli()
