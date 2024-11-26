# pyhydrus
Hydrus API in Python

## Setup

Enter URL, port, and API key information into a new `config.yml` file as shown below:

```yml
url: "http://127.0.0.1:45869"
api_key: "someapikey"
```

Create venv folder and activate before all uses.

```sh
./setup_venv.sh
```
## Test

Open the Hydrus client and enable the client API before running tests.

python -m unittest tests/test.py

Some tests such as request_new_permissions will fail unless the matching menu is open in the hydrus client.
