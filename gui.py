import tkinter as tk
from tkinter import messagebox
import customtkinter as ctk
import threading
import sys

from config import APP_NAME, BASE_DIR
import os
from utils import is_valid_email, is_admin
from auth import is_gmail_registered, register_gmail, verify_email
from email_service import send_password_email, verify_password, clear_password, send_alert_email
from scanner import scan_website
from blocker import block_website, unblock_website, block_category
from project_server import open_project_info
from stats_manager import record_scan, record_block, load_stats

# Initialize CustomTkinter globally
ctk.set_appearance_mode("dark")  # Modes: "System" (standard), "Dark", "Light"
ctk.set_default_color_theme("blue")  # Themes: "blue" (standard), "green", "dark-blue"

class Application(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        self.title(APP_NAME)
        self.geometry("750x650")
        self.resizable(False, False)
        
        icon_path = os.path.join(BASE_DIR, "icon.ico")
        if os.path.exists(icon_path):
            self.iconbitmap(icon_path)
            
        self.create_widgets()
        
        # Check admin status
        if not is_admin():
            messagebox.showwarning("Admin Rights Required", 
                                  "The application is not running with Administrator privileges.\n\n"
                                  "You can scan websites, but blocking/unblocking features will not work.")
                                  
    def create_widgets(self):
        # Main container with padding
        main_frame = ctk.CTkFrame(self, fg_color="transparent")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=30, pady=30)
        
        # Header Section
        header_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        header_frame.pack(fill=tk.X, pady=(0, 20))
        
        ctk.CTkLabel(header_frame, text="MALICIOUS BLOCKER", font=ctk.CTkFont(family="Segoe UI", size=24, weight="bold"), text_color="#00ffcc").pack(anchor=tk.W)
        ctk.CTkLabel(header_frame, text="Protect your system from malicious websites", font=ctk.CTkFont(family="Segoe UI", size=14), text_color="#888888").pack(anchor=tk.W)
        
        # Top Buttons
        top_btn_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        top_btn_frame.pack(fill=tk.X, pady=(0, 20))
        
        ctk.CTkButton(top_btn_frame, text="ℹ Project Info", command=open_project_info, fg_color="#2d2d2d", hover_color="#3d3d3d", text_color="#ffffff", font=ctk.CTkFont(weight="bold")).pack(side=tk.LEFT, padx=(0, 10))
        
        ctk.CTkButton(top_btn_frame, text="📊 Dashboard", command=self.open_dashboard, fg_color="#2d2d2d", hover_color="#3d3d3d", text_color="#ffffff", font=ctk.CTkFont(weight="bold")).pack(side=tk.LEFT, padx=(0, 10))
        
        reg_text = "Update Gmail" if is_gmail_registered() else "Register Gmail"
        self.reg_btn = ctk.CTkButton(top_btn_frame, text=reg_text, command=self.register_gmail_dialog, fg_color="#2d2d2d", hover_color="#3d3d3d", text_color="#ffffff", font=ctk.CTkFont(weight="bold"))
        self.reg_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        ctk.CTkButton(top_btn_frame, text="Block Category", command=self.block_category_dialog, fg_color="#cc3333", hover_color="#ff4444", text_color="#ffffff", font=ctk.CTkFont(weight="bold")).pack(side=tk.LEFT)
        
        # URL Input Section (Card)
        input_card = ctk.CTkFrame(main_frame, corner_radius=10, fg_color="#1e1e1e")
        input_card.pack(fill=tk.X, pady=(0, 20), ipadx=20, ipady=20)
        
        # Use a sub-frame to handle padding properly inside the card
        input_inner = ctk.CTkFrame(input_card, fg_color="transparent")
        input_inner.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        ctk.CTkLabel(input_inner, text="Target URL:", font=ctk.CTkFont(family="Segoe UI", size=14, weight="bold")).pack(anchor=tk.W, pady=(0, 5))
        
        self.url_var = tk.StringVar()
        url_entry = ctk.CTkEntry(input_inner, textvariable=self.url_var, font=ctk.CTkFont(family="Segoe UI", size=14), height=40, border_color="#2d2d2d", fg_color="#121212")
        url_entry.pack(fill=tk.X, pady=(0, 20))
        
        # Action Buttons
        action_btn_frame = ctk.CTkFrame(input_inner, fg_color="transparent")
        action_btn_frame.pack(fill=tk.X)
        
        self.scan_btn = ctk.CTkButton(action_btn_frame, text="🔍 Check Website", font=ctk.CTkFont(weight="bold"), fg_color="#00ccaa", hover_color="#00ffcc", text_color="#000000", height=40, command=self.on_scan)
        self.scan_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        self.block_btn = ctk.CTkButton(action_btn_frame, text="⛔ Block Website", font=ctk.CTkFont(weight="bold"), fg_color="#cc3333", hover_color="#ff4444", text_color="#ffffff", height=40, command=self.on_block)
        self.block_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        self.unblock_btn = ctk.CTkButton(action_btn_frame, text="✅ Unblock Website", font=ctk.CTkFont(weight="bold"), fg_color="#2d2d2d", hover_color="#3d3d3d", text_color="#ffffff", height=40, command=self.on_unblock)
        self.unblock_btn.pack(side=tk.LEFT)
        
        # Status/Results Section (Card)
        results_card = ctk.CTkFrame(main_frame, corner_radius=10, fg_color="#1e1e1e")
        results_card.pack(fill=tk.BOTH, expand=True, ipadx=20, ipady=20)
        
        results_inner = ctk.CTkFrame(results_card, fg_color="transparent")
        results_inner.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        ctk.CTkLabel(results_inner, text="Analysis Results", font=ctk.CTkFont(family="Segoe UI", size=16, weight="bold")).pack(anchor=tk.W, pady=(0, 10))
        
        # Status Label
        self.status_var = tk.StringVar(value="Ready. Enter a URL to scan.")
        self.status_label = ctk.CTkLabel(results_inner, textvariable=self.status_var, font=ctk.CTkFont(family="Segoe UI", size=14))
        self.status_label.pack(anchor=tk.W, pady=(0, 10))
        
        # Detailed Results Text Area
        self.results_text = ctk.CTkTextbox(results_inner, font=ctk.CTkFont(family="Consolas", size=12), fg_color="#121212", text_color="#00ffcc", border_width=1, border_color="#2d2d2d")
        self.results_text.pack(fill=tk.BOTH, expand=True)
        self.results_text.configure(state="disabled")
        
    def append_result(self, text, clear=False):
        self.results_text.configure(state="normal")
        if clear:
            self.results_text.delete("1.0", tk.END)
        self.results_text.insert(tk.END, text + "\n")
        self.results_text.see(tk.END)
        self.results_text.configure(state="disabled")

    def set_ui_state(self, state):
        """Enable or disable buttons during operations."""
        self.scan_btn.configure(state=state)
        self.block_btn.configure(state=state)
        self.unblock_btn.configure(state=state)
        self.update()

    def register_gmail_dialog(self):
        dialog = ctk.CTkInputDialog(text="Enter your Gmail address:", title="Register Gmail")
        email = dialog.get_input()
        if email:
            if is_valid_email(email):
                if register_gmail(email):
                    messagebox.showinfo("Success", "Gmail registered successfully.")
                    self.reg_btn.configure(text="Update Gmail")
                else:
                    messagebox.showerror("Error", "Failed to save registration data.")
            else:
                messagebox.showerror("Invalid Input", "Please enter a valid Gmail address.")

    def authenticate_action(self):
        """
        Perform 2FA authentication workflow.
        Returns True if successful, False otherwise.
        """
        if not is_gmail_registered():
            messagebox.showwarning("Registration Required", "Please register your Gmail address first.")
            return False
            
        dialog = ctk.CTkInputDialog(text="Enter your registered Gmail address:", title="Authentication")
        email = dialog.get_input()
        if not email:
            return False
            
        if not verify_email(email):
            messagebox.showerror("Authentication Failed", "The email does not match the registered account.")
            return False
            
        # Send password
        self.status_var.set("Sending authentication password...")
        self.update()
        
        success, msg = send_password_email(email)
        if not success:
            messagebox.showerror("Email Error", f"Failed to send password:\n{msg}")
            self.status_var.set("Authentication failed.")
            return False
            
        messagebox.showinfo("Password Sent", "An authentication password has been sent to your registered Gmail address.")
        
        pass_dialog = ctk.CTkInputDialog(text="Enter the authentication password sent to your email:", title="Verify Password")
        password = pass_dialog.get_input()
        
        if not password:
            clear_password()
            self.status_var.set("Authentication cancelled.")
            return False
            
        if verify_password(password):
            clear_password()
            return True
        else:
            clear_password()
            messagebox.showerror("Authentication Failed", "Incorrect password.")
            self.status_var.set("Authentication failed.")
            return False

    def on_scan(self):
        url = self.url_var.get().strip()
        if not url:
            messagebox.showwarning("Input Required", "Please enter a URL to scan.")
            return
            
        self.set_ui_state("disabled")
        self.status_var.set("Scanning website...")
        self.append_result(f"[*] Starting scan for: {url}", clear=True)
        
        # Run scan in a separate thread to keep UI responsive
        def scan_thread():
            status, message, stats = scan_website(url)
            # Lazy-load heavy ML and LLM libraries to prevent startup lag
            from ml_model import predict_url_safety
            from llm_explainer import explain_threat
            
            # ML Detection
            is_malicious_ml, confidence = predict_url_safety(url)
            
            # LLM Explanation
            heuristics = stats.get('heuristic_warnings', [])
            explanation = explain_threat(url, status, heuristics, confidence)
            
            record_scan(is_malicious_ml or status == "MALICIOUS")
            
            # Update UI back on main thread
            self.after(0, lambda: self.handle_scan_result(status, message, stats, is_malicious_ml, confidence, explanation))
            
        threading.Thread(target=scan_thread, daemon=True).start()
        
    def handle_scan_result(self, status, message, stats, is_malicious_ml, confidence, explanation):
        self.status_var.set(f"Scan completed. Status: {status}")
        self.append_result(f"Status: {status}")
        self.append_result(message)
        
        self.append_result("\nAI/ML Detection:")
        self.append_result(f"- ML Confidence of Threat: {confidence}%")
        self.append_result(f"- AI Explanation:\n  {explanation}")
        
        if stats:
            self.append_result("\nStatistics:")
            self.append_result(f"- Malicious: {stats.get('malicious', 0)}")
            self.append_result(f"- Suspicious: {stats.get('suspicious', 0)}")
            self.append_result(f"- Harmless: {stats.get('harmless', 0)}")
            self.append_result(f"- Undetected: {stats.get('undetected', 0)}")
            
            cert_info = stats.get('cert_info')
            if cert_info:
                self.append_result("\nHTTPS Certificate:")
                if cert_info.get("status") == "success":
                    self.append_result(f"- Issued to: {cert_info.get('subject')}")
                    self.append_result(f"- Issuer: {cert_info.get('issuer')}")
                    self.append_result(f"- Expires: {cert_info.get('expires')}")
                else:
                    self.append_result(f"- {cert_info.get('message')}")
                    
            heuristics = stats.get('heuristic_warnings')
            if heuristics:
                self.append_result("\nHeuristic Analysis:")
                for w in heuristics:
                    self.append_result(f"[!] {w}")
            elif heuristics is not None:
                self.append_result("\nHeuristic Analysis: No suspicious patterns found.")
            
        # Change status label color based on status
        if status == "MALICIOUS":
            self.status_label.configure(text_color="#ff4444")
        elif status == "SUSPICIOUS":
            self.status_label.configure(text_color="#ffaa00")
        elif status == "SAFE":
            self.status_label.configure(text_color="#00ffcc")
        else:
            self.status_label.configure(text_color="#e0e0e0")
            
        self.set_ui_state("normal")

    def on_block(self):
        url = self.url_var.get().strip()
        if not url:
            messagebox.showwarning("Input Required", "Please enter a URL to block.")
            return
            
        if not self.authenticate_action():
            return
            
        self.status_var.set("Blocking website...")
        self.update()
        
        success, message = block_website(url)
        if success:
            record_block()
            
            # Send alert email
            email_dialog = ctk.CTkInputDialog(text="Enter registered email for alert notification:", title="Security Alert")
            recip = email_dialog.get_input()
            if recip:
                send_alert_email(recip, url, "High Risk")
                
            messagebox.showinfo("Success", message)
            self.append_result(f"[*] {message}")
            self.status_var.set("Website blocked.")
        else:
            messagebox.showerror("Error", message)
            self.append_result(f"[!] Block failed: {message}")
            self.status_var.set("Block operation failed.")

    def on_unblock(self):
        url = self.url_var.get().strip()
        if not url:
            messagebox.showwarning("Input Required", "Please enter a URL to unblock.")
            return
            
        if not self.authenticate_action():
            return
            
        self.status_var.set("Unblocking website...")
        self.update()
        
        success, message = unblock_website(url)
        if success:
            messagebox.showinfo("Success", message)
            self.append_result(f"[*] {message}")
            self.status_var.set("Website unblocked.")
        else:
            messagebox.showerror("Error", message)
            self.append_result(f"[!] Unblock failed: {message}")
            self.status_var.set("Unblock operation failed.")

    def block_category_dialog(self):
        cat = ctk.CTkInputDialog(text="Enter category to block (e.g., 'Adult', 'Social Media', 'Gambling'):", title="Block Category").get_input()
        if cat:
            if not self.authenticate_action():
                return
            success, msg = block_category(cat)
            if success:
                record_block(count=5) # Approximation
                messagebox.showinfo("Success", msg)
                self.append_result(f"[*] {msg}")
            else:
                messagebox.showerror("Error", msg)

    def open_dashboard(self):
        dash = ctk.CTkToplevel(self)
        dash.title("Security Dashboard")
        dash.geometry("400x300")
        dash.resizable(False, False)
        
        ctk.CTkLabel(dash, text="Real-Time Security Dashboard", font=ctk.CTkFont(size=18, weight="bold")).pack(pady=20)
        
        stats = load_stats()
        frame = ctk.CTkFrame(dash, corner_radius=10)
        frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))
        
        ctk.CTkLabel(frame, text=f"Total URL Scans: {stats['total_scans']}", font=ctk.CTkFont(size=14)).pack(anchor=tk.W, padx=20, pady=(20, 10))
        ctk.CTkLabel(frame, text=f"Safe URLs Detected: {stats['safe_detected']}", font=ctk.CTkFont(size=14), text_color="#00ffcc").pack(anchor=tk.W, padx=20, pady=5)
        ctk.CTkLabel(frame, text=f"Malicious URLs Detected: {stats['malicious_detected']}", font=ctk.CTkFont(size=14), text_color="#ff4444").pack(anchor=tk.W, padx=20, pady=5)
        ctk.CTkLabel(frame, text=f"Total Domains Blocked: {stats['total_blocks']}", font=ctk.CTkFont(size=14)).pack(anchor=tk.W, padx=20, pady=(10, 20))

