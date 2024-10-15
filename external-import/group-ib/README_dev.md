# OpenCTI Connector


[![Python](https://img.shields.io/badge/python-v3.6.8+-blue?logo=python)](https://python.org/downloads/release/python-368/)
[![cyberintegrations](https://img.shields.io/badge/cyberintegrations-v0.6.6+-orange?)](https://github.com/cyberintegrations/releases/tag/0.6.6/)
[![OpenCTI](https://img.shields.io/badge/opencti-v6.2.0+-orange?)](https://github.com/OpenCTI-Platform/opencti/releases/tag/6.2.0)


The OpenCTI Connector


## **Content**

As OpenCTI has a dependency on ElasticSearch, you have to set vm.max_map_count before running the containers, 
as mentioned in the [ElasticSearch documentation](https://www.elastic.co/guide/en/elasticsearch/reference/current/docker.html#docker-cli-run-prod-mode).

```sh
sudo sysctl -w vm.max_map_count=1048575
```

To make this parameter persistent, add the following to the end of your /etc/sysctl.conf:

```sh
vm.max_map_count=1048575
```


```sh
$ pip3 install black flake8 pycti
# Fork the current repository, then clone your fork
$ git clone https://github.com/YOUR-USERNAME/connectors.git
$ cd connectors
$ git remote add upstream https://github.com/OpenCTI-Platform/connectors.git
# Create a branch for your feature/fix
$ git checkout -b [branch-name]
# Copy the appropriate template directory for the connector type
$ cp -r templates/$connector_type $connector_type/$myconnector
$ cd $connector_type/$myconnector
$ ls -R
# Dockerfile              docker-compose.yml      requirements.txt
# README.md               entrypoint.sh           src

./src:
# lib     main.py

./src/lib:
# $connector_type.py
```

```sh
$ grep -Ri template .
```

```sh
$ virtualenv env
$ source ./env/bin/activate
$ pip3 install -r requirements
$ cp config.yml.sample config.yml
# Define the opencti url and token, as well as the connector's id
$ vim config.yml
$ python3 main.py
```

```sh
# Linting with flake8 contains no errors or warnings
$ flake8 --ignore=E,W
# Verify formatting with black
$ black .
# All done! ✨ 🍰 ✨
# 1 file left unchanged.
# Verify import sorting
$ isort --profile black .
# Fixing /path/to/connector/file.py
# Push you feature/fix on Github
$ git add [file(s)]
$ git commit -m "[connector_name] descriptive message"
$ git push origin [branch-name]
# Open a pull request with the title "[connector_name] message"
```
