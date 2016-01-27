import pytest


########################################
# Options
########################################

def pytest_addoption(parser):
    parser.addoption(
        '--db',
        action='store',
        default='sql',
        help='DB to use: sql / mongo',
    )


@pytest.fixture(scope='session')
def option_db(request):
    return request.config.getoption('--db')
