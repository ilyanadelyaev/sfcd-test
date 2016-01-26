set -x

rm -rf ./venv
rm -rf ./.cache
find ./sfcd -name "*.pyc" -exec rm -rf {} \;
