set -x

virtualenv ./venv
source ./venv/bin/activate

pip install -r ./requirements.txt

echo type: \"source ./venv/bin/activate\"
