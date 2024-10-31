'''parse_auth_results.py | author: rhawk117
NOTE
Used to parse out the Authentication Results
and X-Forefront-Antispam-Report headers from 
an email into dataclasses. 

These headers usually will immediately
reveal whethe or not an email is spam or also 
if the sender is spoofing their domain and also
can provide useful information about the sender 
as well.
'''
from dataclasses import dataclass, fields
from pprint import pprint
import re
import logging
from mailbox import mbox
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import as_completed
import tqdm

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('header_parse.log'),
        logging.StreamHandler()
    ]
)


def show_data(data: object) -> None:
    for field in fields(data):
        print(f"{field.name}: {getattr(data, field.name)}")


@dataclass
class XForefrontAntispamReport:
    ip_address: str = None
    country: str = None
    lang: str = None
    scl: str = None
    h_addres: str = None

    @staticmethod
    def create(raw):
        splited = raw.split(";")
        fields = {}
        for i in splited:
            key, value = safe_parse(i)
            fields[key] = value
        return XForefrontAntispamReport(
            ip_address=fields.get('CIP', "N/A"),
            country=fields.get('CTRY', "N/A"),
            lang=fields.get('LANG', "N/A"),
            scl=fields.get('SCL', "N/A"),
            h_addres=fields.get('H', "N/A")
        )


def extract_value(pattern: re.Pattern, auth_string: str, default=None) -> str:
    match = pattern.search(auth_string)
    return match.group(1) if match else default


mail_auth_pat = {
    'spf': re.compile(r'spf=(\w+)'),
    'sender_ip': re.compile(r'sender IP is ([\d.]+)'),
    'smtp_mailfrom': re.compile(r'smtp\.mailfrom=([\w.]+)'),
    'dkim': re.compile(r'dkim=(\w+)'),
    'dmarc': re.compile(r'dmarc=(\w+)'),
    'dmarc_action': re.compile(r'action=(\w+)'),
    'header_from': re.compile(r'header\.from=([\w.]+)'),
    'compauth': re.compile(r'compauth=(\w+)'),
    'compauth_reason': re.compile(r'reason=(\d+)'),
}


@dataclass
class MailAuthResult:
    spf: str = None
    sender_ip: str = None
    smtp_mailfrom: str = None
    dkim: str = None
    dkim_signature: str = None
    dmarc: str = None
    dmarc_action: str = None
    header_from: str = None
    compauth: str = None
    compauth_reason: str = None

    @staticmethod
    def create(auth_result: str) -> 'MailAuthResult':
        global mail_auth_pat
        obj = MailAuthResult()
        for field in fields(obj):
            if field.name == 'dkim_signature':
                result = 'verified' if 'signature was verified' in auth_result else 'not verified'
            else:
                result = extract_value(
                    mail_auth_pat[field.name], auth_result, 'N/A')
            setattr(obj, field.name, result)
        return obj


def safe_parse(raw: str) -> tuple:
    if not ":" in raw:
        return ('Unknown', 'N/A')
    splitted = raw.split(":")
    return (splitted[0], splitted[1])


def create_counter_dict(data_class):
    return {field.name: 0 for field in fields(data_class)}


def count_na_values(etr: mbox):
    logging.info("Starting to count success rates")
    sample_auth = create_counter_dict(MailAuthResult())
    sample_xfore = create_counter_dict(XForefrontAntispamReport())

    def get_counts(counter, obj):
        for field in fields(obj):
            if getattr(obj, field.name) == 'N/A':
                counter[field.name] += 1

    def process_message(msg, auth_counts, xfore_counts):
        auth_str = msg.get('Authentication-Results', 'N/A')
        xfore_str = msg.get('X-Forefront-Antispam-Report', 'N/A')
        auth_obj = MailAuthResult.create(auth_str)
        xfore_obj = XForefrontAntispamReport.create(xfore_str)
        get_counts(auth_counts, auth_obj)
        get_counts(xfore_counts, xfore_obj)

    def display_results(counter, obj_name):
        logging.info(f"N/A counts for {obj_name}")
        for key, value in counter.items():
            logging.info(f"{key}: {value} => {value / len(etr):.2f}%")

    with ThreadPoolExecutor() as executor:
        future_to_email = {
            executor.submit(process_message, msg, sample_auth, sample_xfore): msg
            for msg in etr
        }
        for future in tqdm.tqdm(as_completed(future_to_email), total=len(etr)):
            future.result()

    display_results(sample_auth, 'MailAuthResult')
    display_results(sample_xfore, 'XForefrontAntispamReport')


'''NOTE on success rates of parser  
almost all fields had an above 90% success rate
sometimes they are not included which is why they 
may be N/A
'''


def test_success_rates(mbox_file):
    logging.info("Testing Success Rates")
    count_na_values(mbox_file)


def main() -> None:
    pass


if __name__ == '__main__':
    main()