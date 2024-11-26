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

python -m unittest tests/test.py
