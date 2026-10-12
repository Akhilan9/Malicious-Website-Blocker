import os
from google import genai
from config import BASE_DIR
from dotenv import load_dotenv

# We load explicitly to catch any mid-session updates to .env
load_dotenv(os.path.join(BASE_DIR, ".env"), override=True)
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")

def explain_threat(url, vt_status, heuristics, ml_confidence):
    """
    Uses Gemini LLM to provide a beginner-friendly explanation of why the URL might be unsafe.
    """
    if not GEMINI_API_KEY:
        return "Gemini API key not found. Cannot generate AI explanation."
        
    try:
        client = genai.Client(api_key=GEMINI_API_KEY)
        
        heuristic_str = "\n".join(heuristics) if heuristics else "None"
        
        prompt = f"""
        You are a cybersecurity expert building a beginner-friendly desktop application.
        The user has scanned the following URL: {url}
        
        Here are the scan results:
        - VirusTotal Status: {vt_status}
        - Local Machine Learning Threat Confidence: {ml_confidence}%
        - Local Heuristics Warnings: {heuristic_str}
        
        Write a short (2-3 sentences), beginner-friendly explanation of whether this website is safe or dangerous, and why. 
        Do not use complex technical jargon. Be direct and helpful.
        """
        
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt,
        )
        return response.text.strip()
    except Exception as e:
        return f"Error generating explanation: {e}"
