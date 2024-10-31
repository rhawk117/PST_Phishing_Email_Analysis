# body_parser.py
import re
from email.message import EmailMessage
from bs4 import BeautifulSoup
from tqdm import tqdm
import concurrent.futures
import mailbox
import logging

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('body_parser.log'),
        logging.StreamHandler()
    ]
)

class BodyParser:
    def __init__(self, email_msg: EmailMessage):
        self.msg: EmailMessage = email_msg
        self.contents: str = ''
        self.is_invalid: bool = False
        self._parse_body()

    def _decode_payload(self, part, charset) -> str:
        """Decode the payload of an email part."""
        try:
            payload = part.get_payload(decode=True)
            if payload:
                return payload.decode(charset, errors='replace')
        except Exception:
            self.is_invalid = True
        return ''

    def _parse_text_plain(self, part) -> str:
        """Parse text/plain content."""
        charset = part.get_content_charset() or 'utf-8'
        text = self._decode_payload(part, charset)
        return self._clean_whitespace(text)

    def _parse_text_html(self, part) -> str:
        """Parse text/html content."""
        charset = part.get_content_charset() or 'utf-8'
        html_content = self._decode_payload(part, charset)
        if not html_content:
            return ''
        soup = BeautifulSoup(html_content, 'html.parser')
        text = soup.get_text(separator='\n')
        return self._clean_whitespace(text)

    def _parse_part(self, part) -> str:
        """Parse a single part of the email."""
        content_type = part.get_content_type()
        content_disposition = part.get_content_disposition()

        if content_disposition and content_disposition != 'inline':
            return ''
        if content_type == 'text/plain':
            return self._parse_text_plain(part)
        elif content_type == 'text/html':
            return self._parse_text_html(part)

        return ''

    def _parse_multi_part(self) -> str:
        """Parse a multi-part email message."""
        body = ''
        for part in self.msg.walk():
            body += self._parse_part(part)
            if body and part.get_content_type() == 'text/plain':
                break
        return body

    def _parse_single(self) -> str:
        return self._parse_part(self.msg)

    def _parse_body(self) -> str:
        """Parse the body of an email message."""
        try:
            self.contents = self._parser_routine()
        except Exception:
            self.is_invalid = True
            self.contents = 'Unknown'

    def _parser_routine(self) -> str:
        body = ''
        if self.msg.is_multipart():
            body = self._parse_multi_part()
        else:
            body = self._parse_single()
        return body.strip() or 'Unknown'

    @staticmethod
    def _clean_whitespace(text: str) -> str:
        text = re.sub(r'[ \t]+', ' ', text)
        lines = [line.strip() for line in text.splitlines()]
        non_empty_lines = [line for line in lines if line]
        cleaned_text = '\n'.join(non_empty_lines)
        return cleaned_text


def process_email(msg: mailbox.Message, case_num: int, failed_payloads: list) -> bool:
    parser = BodyParser(msg)
    result = parser.contents != 'Unknown' or parser.is_invalid
    return result

''' NOTE about success rates 
-The Body Parser out of 60K emails
    -99.96% parsed without error
-After hyperfixating on the 0.04% failed emails
I determined that the emails 
A. Were empty 
B. Were corrupted 
C. Failed to be converted into a EmailMessage object 
and as such the payload could not be extracted 


'''
def test_body_parser(mbox_etr1: mailbox.mbox):
    logging.info("starting testing")
    results: list[bool] = []
    failed_payloads: list[str] = []
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_to_email = {
            executor.submit(process_email, msg, idx, failed_payloads): msg
            for idx, msg in enumerate(mbox_etr1, start=1)
        }
        for future in tqdm(concurrent.futures.as_completed(future_to_email), total=31988):
            try:
                result = future.result()
                results.append(result)
            except Exception as exc:
                print(f'Email generated an exception: {exc}')
                results.append(False)

    success_count = sum(results)
    total_count = len(results)
    success_rate = (success_count / total_count) * \
        100 if total_count > 0 else 0

    print(f"""
            << RESULTS >>
       +  Successfully parsed: {success_count}
       -  Failed to parse: {total_count - success_count}
       +  Success rate: {success_rate:.2f}%
    """)

    if failed_payloads:
        print("\nRaw payloads of failed emails:")
        for idx, payload in enumerate(failed_payloads, start=1):
            logging.info(f"\n[ Failed Email [{idx}] Payload]:\n{payload}\n")

    logging.info(f"Success Rate: {success_rate:.2f}%")
    logging.info(f"Failed Emails: {total_count - success_count}")
    logging.info(f"Failed Email Payloads: {failed_payloads}")


def main() -> None:
    pass


if __name__ == '__main__':
    main()
