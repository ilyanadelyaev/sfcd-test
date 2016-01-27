secret_key='f556bae6-abd5-42b3-b5d4-e4e340f811c7'

simple_email=$(uuidgen)'@me.me'
simple_password=$(uuidgen)

facebook_email=$(uuidgen)'@me.me'
facebook_id=$(uuidgen)
facebook_token=$(uuidgen)

## test /auth/signup/

echo 'SIGNUP'

declare -a signup_data=(
    # invalid secret
    '{"type":"simple","email":"me@me.me","password":"moo","secret":"invalid_secret"}'
    # invalid type
    '{"type":"invalid_type","secret":"'$secret_key'"}'
    # invalid email
    '{"type":"simple","email":"me.me","secret":"'$secret_key'"}'
    # simple
    '{"type":"simple","email":"'$simple_email'","password":"'$simple_password'","secret":"'$secret_key'"}'
    # invalid password
    '{"type":"simple","email":"'$(uuidgen)'@me.me","secret":"'$secret_key'"}'
    # facebook
    '{"type":"facebook","email":"'$facebook_email'","facebook_id":"'$facebook_id'","facebook_token":"'$facebook_token'","secret":"'$secret_key'"}'
    # invalid facebook_id
    '{"type":"facebook","email":"'$(uuidgen)'@me.me","secret":"'$secret_key'"}'
    # invalid facebook_token
    '{"type":"facebook","email":"'$(uuidgen)'@me.me","facebook_id":"'$(uuidgen)'","secret":"'$secret_key'"}'
)

for i in "${signup_data[@]}"
do
    curl \
        -H "Content-Type: application/json" \
        -X POST \
        -d "$i" \
        --write-out ' st: %{http_code}\n' \
        http://localhost:8080/auth/signup/
done


## test /auth/signin/

echo 'SIGNIN'

declare -a signin_data=(
    # invalid secret
    '{"type":"simple","email":"me@me.me","password":"moo","secret":"invalid_secret"}'
    # invalid type
    '{"type":"invalid_type","email":"'$(uuidgen)'@me.me","secret":"'$secret_key'"}'
    # invalid email
    '{"type":"simple","email":"me.me","secret":"'$secret_key'"}'
    # simple
    '{"type":"simple","email":"'$simple_email'","password":"'$simple_password'","secret":"'$secret_key'"}'
    # invalid password
    '{"type":"simple","email":"'$simple_email'","password":"invalid_password","secret":"'$secret_key'"}'
    # facebook
    '{"type":"facebook","email":"'$facebook_email'","facebook_id":"'$facebook_id'","facebook_token":"'$facebook_token'","secret":"'$secret_key'"}'
    # invalid facebook data
    '{"type":"facebook","email":"'$facebook_email'","facebook_id":"invalid_id","facebook_token":"invalid_token","secret":"'$secret_key'"}'
)

for i in "${signin_data[@]}"
do
    curl \
        -H "Content-Type: application/json" \
        -X POST \
        -d "$i" \
        --write-out ' st: %{http_code}\n' \
        http://localhost:8080/auth/signin/
done
