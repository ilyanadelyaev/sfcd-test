# Test-task for SFCD

Auth API for mobile apps with user registration in database.

Using:
* Flask
* SQLAlchemy
* MongoEngine

Realize POST "/auto/signin" and "/auth/signup" methods for simple auth.
Additionally auth via Facebook, Twitter and Instagram.

## Init
```
./init.sh
source venv/bin/activate
```

## Test
* pytest
* pep8
* pylint
```
./test.sh
```

## Run
```
./run.sh
```

## Clean
```
deactivate
./clean.sh
```
