set -x

PYTHONPATH="./:$PYTHONPATH" python ./sfcd/main.py --config ./config/dev.yaml
