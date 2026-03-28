
class WebScanner:
    """Base scanner class for web vulnerability scanning."""
    
    def __init__(self, target=None, options=None):
        self.target = target
        self.options = options or {}
        self.results = []

    def scan(self):
        """Perform the scan (to be overridden by subclasses)."""
        raise NotImplementedError("Subclasses must implement scan()")

    def get_results(self):
        return self.results