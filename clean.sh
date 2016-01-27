set -x

rm -rf ./venv
rm -rf ./.cache
find ./sfcd -name "*.pyc" -exec rm -rf {} \;
find ./sfcd -name "__pycache__" -exec rm -rf {} \;
