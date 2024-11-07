import os
from pathlib import Path
import json
from typing import Dict, Any

class Settings:
    def __init__(self):
        self.settings_file = Path(__file__).parent / ".streamlit" / "settings.json"
        self.settings_file.parent.mkdir(exist_ok=True)
        self.load_settings()

    def load_settings(self) -> Dict[str, Any]:
        """Load settings from file"""
        if self.settings_file.exists():
            try:
                with open(self.settings_file, 'r') as f:
                    self.settings = json.load(f)
            except:
                self.settings = self.get_default_settings()
        else:
            self.settings = self.get_default_settings()
        return self.settings

    def save_settings(self, settings: Dict[str, Any]) -> None:
        """Save settings to file"""
        with open(self.settings_file, 'w') as f:
            json.dump(settings, f, indent=2)
        self.settings = settings

    def get_default_settings(self) -> Dict[str, Any]:
        """Get default settings"""
        return {
            "api": {
                "username": "",
                "token": ""
            },
            "ai": {
                "model": "gpt-4",
                "temperature": 0.3,
                "api_key": ""
            },
            "ui": {
                "theme": "dark",
                "layout": "wide",
                "notifications": True
            }
        }

    def update_section(self, section: str, data: Dict[str, Any]) -> None:
        """Update a specific settings section"""
        if section in self.settings:
            self.settings[section].update(data)
            self.save_settings(self.settings)

    def get_section(self, section: str) -> Dict[str, Any]:
        """Get a specific settings section"""
        return self.settings.get(section, {})
