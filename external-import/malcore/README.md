## Prerequisites

Some tools are needed before starting to develop. Please check [Ubuntu prerequisites](https://docs.opencti.io/latest/development/environment_ubuntu/) or [Windows prerequisites](https://docs.opencti.io/latest/development/environment_windows/)

## Clone the projects

Fork and clone the git repositories

- https://github.com/OpenCTI-Platform/opencti/ - frontend / backend
- https://github.com/Internet-2-0/Malcore-OpenCTI.git - malcore connector

## 1. Run Dependencies containers

In development dependencies are deployed trough containers. A development compose file is available in `~/opencti/opencti-platform/opencti-dev`

```
cd ~/docker
#Start the stack in background
docker-compose -f ./docker-compose-dev.yml up -d
```

You have now all the dependencies of OpenCTI running and waiting for product to run.

## 2. Run OpenCTI GraphQL

The GraphQL API is developed in JS and with some python code. As it's an "all-in-one" installation, the python environment will be installed in a virtual environment.

```
cd ~/opencti/opencti-platform/opencti-graphql
python3 -m venv .venv --prompt "graphql"
source .venv/bin/activate
pip install --upgrade pip wheel setuptools
yarn install
yarn install:python 
deactivate
```

### Development configuration

The API can be specifically configured with files depending on the starting profile. By default, the default.json file is used and will be correctly configured for local usage **except for admin password**

So you need to create a development profile file. You can duplicate the default file and adapt if for you need.

```
cd ~/opencti/opencti-platform/opencti-graphql/config
cp default.json development.json
```

At minimum adapt the admin part for the password and token.

    ```
    "admin": {
      "email": "admin@opencti.io",
      "password": "MyNewPassord",
      "token": "UUID generated with https://www.uuidgenerator.net"
    }
    ```

### Install / start

Before starting the backend you need to install the nodejs modules

```
cd ~/opencti/opencti-platform/opencti-graphql
yarn install
```

Then you can simply start the backend API with the yarn start command

```
cd ~/opencti/opencti-platform/opencti-graphql
yarn start
```

The platform will start logging some interesting information

```
{"category":"APP","level":"info","message":"[OPENCTI] Starting platform","timestamp":"2023-07-02T16:37:10.984Z","version":"5.8.7"}
{"category":"APP","level":"info","message":"[OPENCTI] Checking dependencies statuses","timestamp":"2023-07-02T16:37:10.987Z","version":"5.8.7"}
{"category":"APP","level":"info","message":"[SEARCH] Elasticsearch (8.5.2) client selected / runtime sorting enabled","timestamp":"2023-07-02T16:37:11.014Z","version":"5.8.7"}
{"category":"APP","level":"info","message":"[CHECK] Search engine is alive","timestamp":"2023-07-02T16:37:11.015Z","version":"5.8.7"}
...
{"category":"APP","level":"info","message":"[INIT] Platform initialization done","timestamp":"2023-07-02T16:37:11.622Z","version":"5.8.7"}
{"category":"APP","level":"info","message":"[OPENCTI] API ready on port 4000","timestamp":"2023-07-02T16:37:12.382Z","version":"5.8.7"}
```

## 3. Run OpenCTI Frontend

### Install / start

Before starting the backend you need to install the nodejs modules

```
cd ~/opencti/opencti-platform/opencti-front
yarn install
```

Then you can simply start the frontend with the yarn start command

```
cd ~/opencti/opencti-platform/opencti-front
yarn start
```

The frontend will start with some interesting information

```
[INFO] [default] compiling...
[INFO] [default] compiled documents: 1592 reader, 1072 normalization, 1596 operation text
[INFO] Compilation completed.
[INFO] Done.
[HPM] Proxy created: /stream  -> http://localhost:4000
[HPM] Proxy created: /storage  -> http://localhost:4000
[HPM] Proxy created: /taxii2  -> http://localhost:4000
[HPM] Proxy created: /feeds  -> http://localhost:4000
[HPM] Proxy created: /graphql  -> http://localhost:4000
[HPM] Proxy created: /auth/**  -> http://localhost:4000
[HPM] Proxy created: /static/flags/**  -> http://localhost:4000
```

The web UI should be accessible on [http://127.0.0.1:3000](http://127.0.0.1:3000/)

## 4. Run Worker

Running a worker is required when you want to develop on the ingestion or import/export connectors.

### Python virtual env

```
cd ~/opencti/opencti-worker/src
python3 -m venv .venv --prompt "worker"
source .venv/bin/activate
pip3 install --upgrade pip wheel setuptools
pip3 install -r requirements.txt
deactivate
```

### Install / start

```
cd ~/opencti/opencti-worker/src
source .venv/bin/activate
python worker.py
```

## 5. Run Malcore Connector

For development purposes, it is easier to simply run the python script locally until everything works as it sould.

```
$ virtualenv env
$ source ./env/bin/activate
$ pip3 install -r requirements 
# Define the opencti url and token, as well as the connector's id
$ vim config.yml
```

```
$ python3 main.py
INFO:root:Listing Threat-Actors with filters null.
INFO:root:Connector registered with ID: a2de809c-fbb9-491d-90c0-96c7d1766000
INFO:root:Starting ping alive thread
```
