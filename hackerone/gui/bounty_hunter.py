import requests
import pandas as pd
import streamlit as st
from typing import Dict, List
from datetime import datetime
from litellm import completion

class BountyHunter:
    def __init__(self, api_username: str, api_token: str):
        self.auth = (api_username, api_token)
        self.headers = {'Accept': 'application/json'}
        self.base_url = "https://api.hackerone.com/v1/hackers"
        
    def get_programs(self) -> List[Dict]:
        """Fetch all public bug bounty programs"""
        try:
            st.write("Fetching programs...") # Debug output
            response = requests.get(
                "https://api.hackerone.com/v1/programs",  # Changed from /hackers/programs
                auth=self.auth,
                headers=self.headers
            )
            response.raise_for_status()
            
            # Debug output
            st.write(f"Response status: {response.status_code}")
            data = response.json()
            st.write(f"Found {len(data.get('data', []))} programs")
            
            return data.get('data', [])
        except requests.exceptions.HTTPError as e:
            st.error(f"HTTP Error: {e.response.status_code} - {e.response.text}")
            return []
        except Exception as e:
            st.error(f"Error fetching programs: {str(e)}")
            return []
        
    def get_hacktivity(self, limit: int = 100) -> List[Dict]:
        """Fetch recent bounty awards"""
        response = requests.get(
            f"{self.base_url}/hacktivity",
            params={'limit': limit},
            auth=self.auth,
            headers=self.headers
        )
        response.raise_for_status()
        return response.json()['data']
        
    def analyze_program(self, program: Dict) -> Dict:
        """Use LiteLLM to analyze program potential"""
        try:
            prompt = f"""
            Analyze this bug bounty program and rate it from 1-10:
            
            Program: {program['attributes']['name']}
            Description: {program['attributes'].get('description', 'N/A')}
            Bounty Range: {program['attributes'].get('bounty_range', 'N/A')}
            
            Consider:
            1. Bounty amounts
            2. Scope size
            3. Technology stack
            4. Program history
            
            Provide:
            {{
                "score": <1-10>,
                "reasoning": "<brief explanation>",
                "recommended_focus": "<suggested vulnerability types>"
            }}
            """
            
            try:
                response = completion(
                    model="gpt-4-1106-preview",  # Using GPT-4 Turbo
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0.7,
                    max_tokens=500,
                    api_key=st.secrets["OPENAI_API_KEY"]
                )
                return response.choices[0].message.content
            except Exception as e:
                st.error(f"LiteLLM API error: {str(e)}")
                return "AI analysis unavailable"
            
            # Ensure we get a valid JSON response
            try:
                return {
                    "score": response.choices[0].message.content.get("score", 5),
                    "reasoning": response.choices[0].message.content.get("reasoning", "Analysis unavailable"),
                    "recommended_focus": response.choices[0].message.content.get("recommended_focus", "General security testing")
                }
            except (AttributeError, KeyError):
                return {
                    "score": 5,
                    "reasoning": "Analysis failed to parse",
                    "recommended_focus": "General security testing"
                }
                
        except Exception as e:
            st.error(f"Analysis failed: {str(e)}")
            return {
                "score": 0,
                "reasoning": f"Analysis error: {str(e)}",
                "recommended_focus": "Analysis unavailable"
            }

    def get_program_stats(self) -> pd.DataFrame:
        """Get statistical overview of programs"""
        programs = self.get_programs()
        stats = []
        
        for program in programs:
            stats.append({
                'name': program['attributes']['name'],
                'bounty_range': program['attributes'].get('bounty_range'),
                'response_efficiency': program['attributes'].get('response_efficiency_percentage'),
                'launch_date': program['attributes'].get('started_accepting_at'),
                'resolved_reports': program['attributes'].get('resolved_report_count')
            })
            
        return pd.DataFrame(stats)
