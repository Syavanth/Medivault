from twilio.rest import Client
import os
from dotenv import load_dotenv

load_dotenv()

class SMSService:
    def __init__(self):
        self.account_sid = os.getenv('TWILIO_ACCOUNT_SID')
        self.auth_token = os.getenv('TWILIO_AUTH_TOKEN')
        self.from_number = os.getenv('TWILIO_PHONE_NUMBER')
        self.client = Client(self.account_sid, self.auth_token)

    def send_reminder(self, phone_number, medicine_name, dosage, timing):
        try:
            message = f"MediVault Reminder: Time to take {medicine_name} - {dosage} at {timing}"
            
            # Format phone number to include country code if not present
            if not phone_number.startswith('+'):
                phone_number = f"+91{phone_number}"  # Assuming Indian numbers by default
            
            self.client.messages.create(
                body=message,
                from_=self.from_number,
                to=phone_number
            )
            return True
        except Exception as e:
            print(f"Error sending SMS: {str(e)}")
            return False

# Create a singleton instance
sms_service = SMSService() 