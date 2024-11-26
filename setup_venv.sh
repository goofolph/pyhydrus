py_command="python3"

if ! type -P $py_command >/dev/null 2>&1; then
    echo "ERROR: $py_command not found."
    exit 1
fi

$py_command -m venv venv

if ! source venv/bin/activate; then
    echo "ERROR: Could not activate virtual environment. Stopping now!"
    exit 1
fi

pip install --upgrade pip
pip install --upgrade wheel
pip install --upgrade -r requirements.txt
