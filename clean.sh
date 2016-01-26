set -x

rm -rf ./venv
rm -rf ./.cache
find ./src -name "*.pyc" -exec rm -rf {} \;
