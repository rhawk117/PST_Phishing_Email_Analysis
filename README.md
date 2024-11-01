# Phishing Email Dataset Parsing Methodology [ON-GOING]

This repository contains the code I created while researching the use of NLP as tool for phishing email forensics. My responsibilities included parsing over 60,000 emails into a CSV file to train the AI model. After extracting this information I will need to manually review each of the rows in the CSV file I will have to manually label each as either spam or phishing and remove any PII from the emails before the data can be processed. I plan on doing this by creating a database and creating an offline web app that uses HTML, CSS and JavaScript that contains regular expressions for common PII and tools to view and classify the information gathered from the dataset. 

## Notes 
* The parsing was conducted on a dataset from Microsoft Outlook so some of headers may be different  
* The research and data set processing is still ongoing 
* Not all of the code written for the research is in this repository for confidentiality purposes. 

## Example Parsing Usage  

```python
from body_parser import BodyParser 
from models import EmailInfo, email_info_factory
from dataclasses import fields
import mailbox

# Show body as a string for all Content Types
def show_body(email_msg: EmailMessage) -> None:
  body = BodyParser(email_msg)
  if not body.is_invalid:
     print(body.contents)

# Generate EmailInfo 
def get_email_info(some_mbox_obj: mailbox.mbox) -> EmailInfo:
    return [email_info_factory(msg) for msg in some_mbox_obj]

# Display Data Parsed [attachment_data, url_data, auth_results, x_antispam_report]
def display(email_info: EmailInfo):
   for names in EmailInfo.attachment_data.attachment_names:
       print(f'-> { name }')
   for field in fields(email_info.auth_results):
       print(f'{ field.name } { getattr(email_info.auth_results, field.name) }')

```

