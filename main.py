
import concurrent.futures
from typing import Optional
from dataclasses import dataclass
from email.message import EmailMessage
from email import policy
import email
import mailbox
import os


@dataclass
class EmailData:
    has_attachments: bool
    content_type: Optional[str]
    body_content: str


@dataclass
class EmailRow:
    subject: str
    from_file: str


def email_factory(fp):
    return email.message_from_binary_file(fp, policy=policy.default)


def is_html_message(message):
    for part in message.walk():
        content_type = part.get_content_type()
        content_disposition = part.get_content_disposition()

        # Skip attachments
        if content_disposition == 'attachment':
            continue

        if content_type == 'text/html':
            return 1
    return 0


def indicate_sum_process(message):
    print(f'>> Processing message: {message["subject"]}')
    return is_html_message(message)


def get_html_count(mbox):
    with concurrent.futures.ThreadPoolExecutor() as executor:
        results = list(executor.map(indicate_sum_process, mbox))
    msg_count = sum(results)
    print(f'Number of messages with HTML content: {msg_count} out of {len(mbox)}')


def main() -> None:
    etr1 = r"E:\SOC_Research\mboxFiles\ETR1\ETR1.mbox"
    if not os.path.exists(etr1):
        raise FileNotFoundError(f'Data Set not found: {etr1}')
    with mailbox.mbox(etr1, factory=email_factory) as mbox:
        print('data set loaded.')
        get_html_count(mbox)


if __name__ == '__main__':
    main()
