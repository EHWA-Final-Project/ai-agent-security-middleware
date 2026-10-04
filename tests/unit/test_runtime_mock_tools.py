import pytest
from pydantic import ValidationError

from runtime.dto import ToolCandidate
from runtime.mock_tools.tools import MockReadFile, MockSendEmail


def test_read_file_returns_fixture_content():
    tool = MockReadFile(
        {
            "documents/meeting.txt": "9월 28일 M1 진행 상황 공유",
        }
    )
    candidate = ToolCandidate(
        tool_call_id="tool-read-001",
        tool_name="read_file",
        tool_arguments={"path": "documents/meeting.txt"},
    )

    result = tool.execute(candidate)

    assert result == {
        "path": "documents/meeting.txt",
        "content": "9월 28일 M1 진행 상황 공유",
    }
    assert tool.call_count == 1


def test_read_file_does_not_read_real_files():
    tool = MockReadFile({})
    candidate = ToolCandidate(
        tool_call_id="tool-read-002",
        tool_name="read_file",
        tool_arguments={"path": "/etc/hosts"},
    )

    with pytest.raises(FileNotFoundError):
        tool.execute(candidate)

    assert tool.call_count == 1


def test_send_email_records_mock_message():
    tool = MockSendEmail()
    candidate = ToolCandidate(
        tool_call_id="tool-email-001",
        tool_name="send_email",
        tool_arguments={
            "to": ["review@example.invalid"],
            "subject": "테스트",
            "body": "합성 회의록",
        },
    )

    result = tool.execute(candidate)

    assert result["accepted"] is True
    assert result["delivery"] == "mock"
    assert tool.call_count == 1
    assert len(tool.outbox) == 1
    assert tool.outbox[0]["tool_call_id"] == "tool-email-001"
    assert tool.outbox[0]["body"] == "합성 회의록"


@pytest.mark.parametrize("recipients", [[], [""]])
def test_invalid_recipients_do_not_create_message(recipients):
    tool = MockSendEmail()
    candidate = ToolCandidate(
        tool_call_id="tool-email-invalid",
        tool_name="send_email",
        tool_arguments={
            "to": recipients,
            "subject": "테스트",
            "body": "합성 데이터",
        },
    )

    with pytest.raises((ValidationError, ValueError)):
        tool.execute(candidate)

    assert tool.call_count == 1
    assert tool.outbox == []


def test_outbox_cannot_be_modified_through_returned_copy():
    tool = MockSendEmail()
    candidate = ToolCandidate(
        tool_call_id="tool-email-002",
        tool_name="send_email",
        tool_arguments={
            "to": ["review@example.invalid"],
            "subject": "테스트",
            "body": "원본",
        },
    )
    tool.execute(candidate)

    snapshot = tool.outbox
    snapshot[0]["body"] = "변경"
    snapshot[0]["to"].append("another@example.invalid")

    assert tool.outbox[0]["body"] == "원본"
    assert tool.outbox[0]["to"] == ["review@example.invalid"]
