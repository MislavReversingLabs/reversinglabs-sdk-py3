import json
from contextlib import nullcontext as does_not_raise

import pytest
import requests

import ReversingLabs
import ReversingLabs.SDK.helper as helper
import ReversingLabs.SDK.tiscale as tiscale


# https://docs.pytest.org/en/7.1.x/explanation/goodpractices.html#do-not-run-via-setuptools

class MockResponse:

    def __init__(self, headers=None, status=200, text=None):
        self._headers = headers if headers else {}
        self._status = status
        self._text = text

    @property
    def text(self):
        return self._text

    @property
    def status_code(self):
        return self._status

    def json(self):
        return json.loads(self._text)

    @property
    def headers(self):
        return self._headers


_HOST = "http://my.tiscale.worker"
_TOKEN = "placeholder"
_WAIT_FOR = 0
_RETRIES = 3
_VERIFY = True

_VALID_FILE_NAME = "some_file.txt"
_INVALID_FILE_NAME = "no_file.txt"

_VALID_TASK_URL = f"{_HOST}/api/tiscale/v1/task/119"
_INVALID_TASK_URL = dict()

_VALID_FILE_CONTENT = "I am a valid text file, scan me if you can."
_VALID_USER_DATA = json.dumps(
    {"callback": {"view": "flat", "report_type": "large", "url": "https://my.webservice.com/path"}})
_INVALID_USER_DATA = _VALID_USER_DATA[:-1]
_VALID_CUSTOM_DATA = json.dumps({"file_source": {"uploader": "malware_analyst", "origin": "i_found_it_on_my_laptop"}})
_INVALID_CUSTOM_DATA = _VALID_CUSTOM_DATA[:-1]

_CUSTOM_TOKEN = "custom_token"

_TASK_NOT_FINISHED_TEXT = """
{
}
"""
_TASK_RESULT_TEXT = """{
    "submitted": 1712234413,
    "task_id": 119,
    "processed": 1712234413,
    "worker_ip": [
        "8.8.8.8"
    ],
    "worker_address": [
        "my.tiscale.worker"
    ],
    "worker_hostname": "my.tiscale.worker",
    "direct_sender": "8.8.8.8",
    "forwarded_for": [
        "1.1.1.1"
    ],
    "custom_data": {
        "file_source": {
            "uploader": "malware_analyst",
            "origin": "i_found_it_on_my_laptop"
        }
    },
    "tc_report": [
        {
            "classification_classification": 1,
            "classification_factor": 5,
            "classification_propagated": false,
            "classification_rca_factor": 5,
            "classification_result": "Text.Format.Graylisting",
            "classification_scan_results_TitaniumCore_Graylisting_classification": 1,
            "classification_scan_results_TitaniumCore_Graylisting_factor": 5,
            "classification_scan_results_TitaniumCore_Graylisting_ignored": false,
            "classification_scan_results_TitaniumCore_Graylisting_rca_factor": 5,
            "classification_scan_results_TitaniumCore_Graylisting_result": "Text.Format.Graylisting",
            "classification_scan_results_TitaniumCore_Graylisting_type": "internal",
            "classification_scan_results_TitaniumCore_Graylisting_version": "4.1.2.0",
            "info_file_entropy": 2.235926350629033,
            "info_file_file_name": "some_file.txt",
            "info_file_file_path": "some_file.txt",
            "info_file_file_subtype": "None",
            "info_file_file_type": "Text",
            "info_file_hashes_md5": "872002aaa5df50c813fd3443dc0bf561",
            "info_file_hashes_rha0": "59d471a86f1a2ab253db68d5086033a07e5210e2",
            "info_file_hashes_sha1": "59d471a86f1a2ab253db68d5086033a07e5210e2",
            "info_file_hashes_sha256": "6b3f75ef9b043a4f002e22a854a86fc9e496bc6bbc1f116761528d5dfbfc6fce",
            "info_file_size": 7,
            "info_statistics_file_stats_0_count": 1,
            "info_statistics_file_stats_0_identifications_0_count": 1,
            "info_statistics_file_stats_0_identifications_0_name": "Unknown",
            "info_statistics_file_stats_0_subtype": "None",
            "info_statistics_file_stats_0_type": "Text",
            "story_0_caption": "Description",
            "story_0_content": "This file (SHA1: 59d471a86f1a2ab253db68d5086033a07e5210e2) is a text file. There are no extracted files.",
            "story_1_caption": "Classification",
            "story_1_content": "The file was classified as goodware, using TitaniumCore graylisting classifier.",
            "tags": [
                "graylisting"
            ]
        }
    ]
}
"""


@pytest.fixture
def valid_file_path(tmp_path):
    f = tmp_path / _VALID_FILE_NAME
    f.write_text(_VALID_FILE_CONTENT)
    return f


@pytest.fixture
def valid_file(valid_file_path):
    return str(valid_file_path.absolute())


@pytest.fixture
def invalid_file(tmp_path):
    f = tmp_path / _INVALID_FILE_NAME
    return str(f.absolute())


@pytest.fixture
def uut():
    return tiscale.TitaniumScale(
        host=_HOST,
        token=_TOKEN,
        wait_time_seconds=_WAIT_FOR,
        retries=_RETRIES,
        verify=_VERIFY,
    )


def test_tiscale_object():
    invalid_host = "my.host"
    valid_host = f"https://{invalid_host}"
    token = "my_mock_token"

    uut = tiscale.TitaniumScale(
        host=valid_host,
        token=token,
        verify=True
    )

    assert uut._url == valid_host + "{endpoint}"

    with pytest.raises(
            helper.WrongInputError,
            match=r"host parameter must contain a protocol definition at the beginning."
    ):
        tiscale.TitaniumScale(host=invalid_host, token=token)

    user_agent = uut._headers.get("User-Agent")
    assert ReversingLabs.SDK.__version__ in user_agent


def test_connection(monkeypatch, uut):
    def mock_get(*args, **kwargs):
        return MockResponse()

    monkeypatch.setattr(requests, "get", mock_get)
    _ = uut.test_connection()


def test_connection_error(monkeypatch, uut):
    def mock_get(*args, **kwargs):
        return MockResponse(status=400)

    monkeypatch.setattr(requests, "get", mock_get)
    with pytest.raises(helper.BadRequestError) as _:
        _ = uut.test_connection()


@pytest.mark.parametrize(
    "values, exception",
    [
        ((_VALID_USER_DATA, _VALID_CUSTOM_DATA), does_not_raise()),
        ((_INVALID_USER_DATA, _VALID_CUSTOM_DATA), pytest.raises(helper.WrongInputError)),
        ((_VALID_USER_DATA, _INVALID_CUSTOM_DATA), pytest.raises(helper.WrongInputError)),
    ],
)
def test_upload_sample_from_path(monkeypatch, uut, valid_file, values, exception):
    task_url = f"{_HOST}/api/tiscale/v1/task/117"
    user_data, custom_data = values

    def mock_post(*args, **kwargs):
        return MockResponse(
            text=task_url,
        )

    monkeypatch.setattr(requests, "post", mock_post)

    with exception:
        response = uut.upload_sample_from_path(
            file_path=valid_file,
            custom_token=_CUSTOM_TOKEN,
            user_data=user_data,
            custom_data=custom_data,
        )
        assert response.text == task_url
        assert response.status_code == 200


def test_upload_sample_from_path_not_string(uut):
    with pytest.raises(helper.WrongInputError) as e:
        _ = uut.upload_sample_from_path(
            file_path=dict(),  # noqa
            custom_token=_CUSTOM_TOKEN,
            user_data=_VALID_USER_DATA,
        )

    assert str(e.value).startswith("file_path must be a string."), f"{e.value}"


def test_upload_sample_from_path_missing_file(uut, invalid_file):
    with pytest.raises(helper.WrongInputError) as e:
        _ = uut.upload_sample_from_path(
            file_path=invalid_file,
            custom_token=_CUSTOM_TOKEN,
            user_data=_VALID_USER_DATA,
        )

    assert str(e.value).startswith("Error while opening file"), f"{e.value}"


@pytest.mark.parametrize(
    "values, exception",
    [
        ((_VALID_USER_DATA, _VALID_CUSTOM_DATA), does_not_raise()),
        ((_INVALID_USER_DATA, _VALID_CUSTOM_DATA), pytest.raises(helper.WrongInputError)),
        ((_VALID_USER_DATA, _INVALID_CUSTOM_DATA), pytest.raises(helper.WrongInputError)),
    ],
)
def test_upload_sample_from_file(monkeypatch, uut, valid_file_path, values, exception):
    user_data, custom_data = values

    def mock_post(*args, **kwargs):
        return MockResponse(
            text=_VALID_TASK_URL,
        )

    monkeypatch.setattr(requests, "post", mock_post)

    with exception, open(valid_file_path, "rb") as handle:
        response = uut.upload_sample_from_file(
            file_source=handle,
            custom_token=_CUSTOM_TOKEN,
            user_data=user_data,
            custom_data=custom_data,
        )
        assert response.text == _VALID_TASK_URL
        assert response.status_code == 200


def test_upload_sample_from_file_bad_handle(uut, invalid_file):
    with pytest.raises(helper.WrongInputError) as e:
        _ = uut.upload_sample_from_file(
            file_source=dict(),  # noqa
            custom_token=_CUSTOM_TOKEN,
            user_data=_VALID_USER_DATA,
        )

    assert str(e.value).startswith("file_source parameter must be a file"), f"{e.value}"


@pytest.mark.parametrize(
    "values, exception",
    [
        ((_VALID_TASK_URL, True), does_not_raise()),
        ((_INVALID_TASK_URL, True), pytest.raises(helper.WrongInputError)),
        ((_VALID_TASK_URL, None), pytest.raises(helper.WrongInputError)),
    ],
)
def test_get_results(monkeypatch, uut, values, exception):
    task_url, full_report = values

    def mock_get(*args, **kwargs):
        return MockResponse(
            text=_TASK_RESULT_TEXT,
        )

    monkeypatch.setattr(requests, "get", mock_get)
    with exception:
        response = uut.get_results(task_url, full_report)
        assert response.status_code == 200


def test_get_result_retries(monkeypatch, uut):
    call_count = 0

    def mock_get(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        return MockResponse(
            text=_TASK_NOT_FINISHED_TEXT,
        )

    monkeypatch.setattr(requests, "get", mock_get)
    result = uut.get_results(_VALID_TASK_URL, True)
    assert result is None
    assert call_count == _RETRIES + 1


"""
def test_upload_sample_and_get_results():
    pass


def test_list_processing_task_info():
    pass


def test_delete_processing_task():
    pass


def test_delete_multiple_tasks():
    pass


def test_get_yara_id():
    pass

"""
