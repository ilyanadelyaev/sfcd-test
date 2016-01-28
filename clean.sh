set -x

rm -rf ./venv
rm -rf ./.cache
rm -rf ./logs
find ./sfcd -name "*.pyc" -exec rm -rf {} \;
find ./sfcd -name "__pycache__" -exec rm -rf {} \;
