'''NOTE author: rhawk117
models.py

The schema for the CSV and also (an 
abridged version of the schema) for the 
database tables

message_id [VARCHAR]: is used as the PK  
'''
import concurrent.futures
from typing import Optional
from dataclasses import dataclass, asdict
from email.message import EmailMessage
import mailbox
# import traceback
import logging
# project imports
from body_parser import BodyParser
from parse_auth_results import (
    XForefrontAntispamReport, MailAuthResult
)
import re
from urllib.parse import urlparse, parse_qs, unquote
import tqdm
import pandas as pd
import os

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('main.log'),
        logging.StreamHandler()
    ]
)


# models for csv rows
@dataclass
class AttachmentData:
    has_attachments: bool
    attachment_count: Optional[int]
    attachment_names: Optional[list[str]]


@dataclass
class UrlData:
    has_urls: bool
    url_count: Optional[int]
    urls: Optional[list[str]]


@dataclass
class Classification:
    from_file: str  # which dataset file
    is_spam: bool
    is_phishing: bool
    is_reviewed: bool  # i.e has been reviewed by a human


@dataclass
class EmailInfo:
    sender: str
    body: str
    subject: str
    date: str
    message_id: str
    reply_to: Optional[str]

    attachment_data: AttachmentData
    url_data: UrlData
    classification: Classification
    auth_results: MailAuthResult
    x_antispam_report: XForefrontAntispamReport


def email_info_factory(msg: EmailMessage) -> None:
    body = BodyParser(msg).contents
    x_fore = msg.get('X-Forefront-Antispam-Report', 'N/A')
    auth = msg.get('Authentication-Results', 'N/A')

    attach = get_attachment_info(msg)

    urls = extract_urls_from_body(body)

    x_antispam_report = XForefrontAntispamReport.create(x_fore)
    auth_results = MailAuthResult.create(auth)

    subject = msg.get('subject', 'N/A')
    msg_from = msg.get('from', 'N/A')
    msg_date = msg.get('date', 'N/A')
    msg_id = msg.get('message-id', 'N/A')
    msg_reply_to = msg.get('reply-to', 'N/A')

    msg_data = EmailInfo(
        sender=msg_from,
        body=body,
        subject=subject,
        date=msg_date,
        message_id=msg_id,
        reply_to=msg_reply_to,
        attachment_data=attach,
        url_data=urls,
        classification=default_classification('etr1'),
        auth_results=auth_results,
        x_antispam_report=x_antispam_report
    )
    return msg_data


def process_email(msg: EmailMessage) -> Optional[dict]:
    try:
        email_info = email_info_factory(msg)
        email_dict = extract_subclasses(email_info)
        return email_dict
    except Exception:
        pass 

def mbox_to_csv(
    data_set: mailbox.mbox,
    output_path: str,
    include_headers: bool
) -> None:

    total_emails = len(data_set)

    max_workers = min(32, (os.cpu_count() or 1) + 4)

    email_data_list = []
    failed_indexes = []
    data_set = list(data_set)
    total_emails = len(data_set)
    with concurrent.futures.ProcessPoolExecutor(max_workers=max_workers) as executor:
        results = executor.map(process_email, data_set, chunksize=100)
        for idx, email_dict in enumerate(tqdm.tqdm(
                results, total=total_emails, desc="Exporting to CSV", unit="emails")):
            if email_dict:
                email_data_list.append(email_dict)
            else:
                failed_indexes.append(idx)

    df = pd.DataFrame(email_data_list)
    df.to_csv(output_path, index=False, mode='a', header=include_headers)
    logging.info(f"Successfully exported {
        total_emails - len(failed_indexes)} emails to {output_path}")
    if failed_indexes:
        logging.info(f"Failed to parse {len(failed_indexes)}")


def parse_dict(sub_dict: dict) -> dict:
    output = {}
    for key, values in sub_dict.items():
        output[key] = values
    return output


def extract_subclasses(msg):
    msg_dict = asdict(msg)
    output: dict = {}
    for key, values in msg_dict.items():
        if isinstance(values, dict):
            result = parse_dict(values)
            output.update(result)
        else:
            output[key] = values
    return output


def get_attachment_info(msg: EmailMessage) -> AttachmentData:
    if not msg.is_multipart():
        return AttachmentData(
            has_attachments=False,
            attachment_count=None,
            attachment_names=None
        )
    attachment_names = []
    attachment_count = 0
    for part in msg.iter_attachments():
        attachment_names.append(part.get_filename())
        attachment_count += 1
    return AttachmentData(
        has_attachments=attachment_count > 0,
        attachment_count=attachment_count,
        attachment_names=attachment_names
    )

# god i hate this feature in outlook
def parse_safelink(url) -> str:
    try:
        parsed_url = urlparse(url)
        if not 'safelinks.protection.outlook.com' in parsed_url.netloc:
            return url
        query_params = parse_qs(parsed_url.query)
        original_url = query_params.get('url', [None])[0]
        if not original_url:
            return url
        return unquote(original_url)
    except Exception as err:
        return url


def extract_urls_from_body(body: str) -> UrlData:
    url_pattern = re.compile(r'https?://\S+')
    urls_found = url_pattern.findall(body)
    urls_parsed = [parse_safelink(url) for url in urls_found]
    return UrlData(
        has_urls=bool(urls_found),
        url_count=len(urls_parsed) if urls_parsed else 0,
        urls=urls_parsed if urls_parsed else ['None']
    )


def default_classification(data_file: str) -> Classification:
    return Classification(
        from_file=data_file,
        is_spam=False,
        is_phishing=False,
        is_reviewed=False
    )
    
def main() -> None:
    pass 

if __name__ == '__main__':
    main()

