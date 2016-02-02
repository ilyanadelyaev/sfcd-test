set -x

PYTHONPATH="./:$PYTHONPATH" python ./sfcd/application.py --config ./config/dev.yaml
