import pytest
from unittest.mock import patch, Mock
from ReversingLabs.SDK.ticloud import TiCloudAPI, FileReputation


@pytest.fixture
def TiCloud_fixture():
    return TiCloudAPI("https://data.reversinglabs.com", "AAAA", "BBBB")


@pytest.fixture
def FileReputation_fixture(TiCloud_fixture):
    return FileReputation(TiCloud_fixture._host, TiCloud_fixture._username, TiCloud_fixture._password)


@patch("ReversingLabs.SDK.ticloud.FileReputation._get_request")
def test_get_file_reputation(mock_get_request, FileReputation_fixture):
    mock_response = Mock()
    mock_response.status_code = 200
    mock_get_request.return_value = mock_response
    response = FileReputation_fixture.get_file_reputation("f5065d35b91b9ec284cbffc85ee78e7ea8a16389")
    assert response.status_code == 200