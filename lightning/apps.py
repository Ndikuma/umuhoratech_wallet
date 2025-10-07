from django.apps import AppConfig


class LightningConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "lightning"
    
    def ready(self):
        # import lightning.signals
        # from .blink_ws_scheduler import schedule_blink_ws
        # schedule_blink_ws()
        pass
