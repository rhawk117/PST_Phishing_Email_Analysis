
from typing import Optional
from dataclasses import dataclass
from email.message import EmailMessage
from email import policy
import email
import mailbox

etr1 = r"E:\SOC_Research\mboxFiles\ETR1\ETR1.mbox"


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



mbox = mailbox.mbox(etr1, factory=email_factory)
print(f'Number of messages: {len(mbox)}')
# get the number of messages with the same content type
content_type_count = {}
for message in mbox:
    content_type = message.get_content_type()
    content_type_count[content_type] = content_type_count.get(content_type, 0) + 1

for idx, message in enumerate(mbox):

    print(f"Message {idx+1}:")
    print(f"Subject: {message.get('Subject', '(No Subject)')}")
    print(f"Content-Type: {message.get_content_type()}")
    input("Press Enter to continue...")

mbox.close()
