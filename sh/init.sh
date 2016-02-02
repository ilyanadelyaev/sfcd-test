set -x

virtualenv ./venv
source ./venv/bin/activate

pip install -r ./requirements.txt

mkdir logs

echo type: \"source ./venv/bin/activate\"
