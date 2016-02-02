# Test-task for SFCD

Auth API for mobile apps with user registration in database.

Using:
* Flask
* SQLAlchemy

Realize POST "/auto/signin" and "/auth/signup" methods for simple auth.
Additionally auth via Facebook.

## Init
```
[sudo] pip install virtualenv
./sh/init.sh
source venv/bin/activate
```

## Test
* pytest
* pep8
* pylint
```
./sh/test.sh
```

## Run
```
./sh/run.sh
```

## Test shots
```
console_0 $ ./sh/run.sh
console_1 $ ./sh/shots.sh
```

## Clean
```
deactivate
./sh/clean.sh
```
