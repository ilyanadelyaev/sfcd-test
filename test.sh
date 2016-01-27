set -x

PYTHONPATH="./:$PYTHONPATH" py.test

pep8 ./sfcd

pylint  --errors-only ./sfcd

# ? coverage
