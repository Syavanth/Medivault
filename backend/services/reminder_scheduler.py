from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from datetime import datetime, time
from models import db, MedicationReminder, User, MedicineEntry
from services.sms_service import sms_service

class ReminderScheduler:
    def __init__(self):
        self.scheduler = BackgroundScheduler()
        self.scheduler.start()

    def schedule_reminder(self, reminder):
        # Convert remind_at time to cron format
        remind_time = reminder.remind_at
        cron_expression = f"{remind_time.minute} {remind_time.hour} * * *"
        
        # Schedule the job
        self.scheduler.add_job(
            self._send_reminder,
            CronTrigger.from_crontab(cron_expression),
            args=[reminder.reminder_id],
            id=f"reminder_{reminder.reminder_id}",
            replace_existing=True
        )

    def _send_reminder(self, reminder_id):
        try:
            reminder = MedicationReminder.query.get(reminder_id)
            if not reminder or not reminder.is_active:
                return

            # Check if reminder is within date range
            today = datetime.now().date()
            if reminder.start_date > today or (reminder.end_date and reminder.end_date < today):
                return

            # Get patient and medicine details
            patient = User.query.get(reminder.patient_id)
            medicine = MedicineEntry.query.get(reminder.medicine_entry_id)

            if patient and patient.phone_number and medicine:
                sms_service.send_reminder(
                    phone_number=patient.phone_number,
                    medicine_name=medicine.name,
                    dosage=medicine.dosage,
                    timing=reminder.remind_at.strftime('%H:%M')
                )
        except Exception as e:
            print(f"Error sending scheduled reminder: {str(e)}")

    def remove_reminder(self, reminder_id):
        job_id = f"reminder_{reminder_id}"
        if self.scheduler.get_job(job_id):
            self.scheduler.remove_job(job_id)

# Create a singleton instance
reminder_scheduler = ReminderScheduler() 