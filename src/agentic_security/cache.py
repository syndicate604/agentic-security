import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional

class SecurityCache:
    def __init__(self, cache_dir: str = ".security_cache"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.results_dir = self.cache_dir / "results"
        self.results_dir.mkdir(exist_ok=True)

    def save_scan_results(self, scan_id: str, results: Dict[str, Any]) -> None:
        """Save scan results to cache"""
        timestamp = datetime.now().isoformat()
        result_file = self.results_dir / f"{scan_id}_{timestamp}.json"
        
        with open(result_file, 'w') as f:
            json.dump({
                'timestamp': timestamp,
                'results': results
            }, f, indent=2)

    def get_scan_results(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve most recent scan results"""
        files = list(self.results_dir.glob(f"{scan_id}_*.json"))
        if not files:
            return None
            
        latest_file = max(files, key=os.path.getctime)
        with open(latest_file) as f:
            return json.load(f)

    def clear_old_results(self, days: int = 30) -> None:
        """Clear results older than specified days"""
        cutoff = datetime.now().timestamp() - (days * 86400)
        for file in self.results_dir.glob("*.json"):
            if file.stat().st_mtime < cutoff:
                file.unlink()
