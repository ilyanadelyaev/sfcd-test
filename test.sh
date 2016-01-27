set -x

PYTHONPATH="./:$PYTHONPATH" py.test --db=sql

pep8 ./sfcd

pylint  --errors-only ./sfcd

# ? coverage
