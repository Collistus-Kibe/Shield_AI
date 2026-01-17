import logging

class QueueLogHandler(logging.Handler):
    """
    A custom logging handler that puts messages into a queue for the GUI.
    """
    def __init__(self, message_queue):
        super().__init__()
        self.message_queue = message_queue

    def emit(self, record):
        try:
            log_entry = self.format(record)
            # Send as dictionary for color coding
            self.message_queue.put({
                'type': 'log',
                'level': record.levelname, 
                'data': log_entry
            })
        except Exception:
            self.handleError(record)