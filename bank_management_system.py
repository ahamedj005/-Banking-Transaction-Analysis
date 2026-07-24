"""
 BANKING TRANSACTION ANALYSIS SYSTEM
 Head Office: Chennai | Branches: Chennai, Coimbatore, Madurai, Salem, Trichy
"""

import streamlit as st
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import hashlib
import uuid
import random
import csv
import os
import shutil
import json
import base64
import time
import logging
from pathlib import Path
from collections import Counter, defaultdict

# GLOBAL CONFIG

st.set_page_config(
    page_title="Chennai Metropolitan Bank | Transaction Analysis System",
    page_icon="🏦",
    layout="wide",
    initial_sidebar_state="expanded",
)

BASE_DIR = Path("bank_data")
BACKUP_DIR = BASE_DIR / "backup"
REPORTS_DIR = BASE_DIR / "reports"

FILES = {
    "customers": BASE_DIR / "customers.csv",
    "accounts": BASE_DIR / "accounts.csv",
    "employees": BASE_DIR / "employees.csv",
    "transactions": BASE_DIR / "transactions.csv",
    "branches": BASE_DIR / "branches.csv",
    "login": BASE_DIR / "login.csv",
    "audit_log": BASE_DIR / "audit_log.csv",
    "activity_log": BASE_DIR / "activity_log.csv",
    "kyc": BASE_DIR / "kyc.csv",
}

BRANCHES = ["Chennai", "Coimbatore", "Madurai", "Salem", "Trichy"]
CUSTOMERS_PER_BRANCH = 80
EMPLOYEES_PER_BRANCH = 10
TOTAL_TRANSACTIONS = 5000

FIRST_NAMES_POOL = [
    "Junaid Ahamed", "Shara", "Tamil Selvan", "Selva Kumar", "Syed Thanveer",
    "Muzamil Khan", "Md Irfan", "Gokulavasan", "Arun Kumar", "Akash Raj",
    "Arshu", "Aiza", "Sastik", "Samj", "Mirza", "Falak", "Md Rayan", "Md Azhan",
    "Safa Mariyam", "Zeeshan Ahamed", "Rahul Sharma", "Priya Nair", "Karthik R",
    "Vishnu Prasad", "Sneha Reddy", "Naveen Kumar", "Harish Kumar", "Nithya S",
    "Rohit Verma", "Deepak Singh", "Kavya Sri", "Ajay Kumar", "Keerthana M",
    "Mohammed Asif", "Imran Khan", "Abdul Rahman", "Santhosh Kumar", "Vignesh R",
    "Suresh Babu", "Divya Lakshmi", "Anitha Devi", "Praveen Kumar", "Bharath Raj",
    "Rakesh Kumar", "Ashwin Kumar", "Monisha R", "Swathi K", "Dinesh Kumar",
    "Nandhini S", "Yogesh Kumar", "Abhishek Jain", "Pooja Sharma", "Varun Reddy",
    "Meena Kumari", "Manikandan P", "Hari Krishna", "Lokesh Kumar", "Reshma Begum",
    "Ahamed Faisal", "Mohammed Zubair", "Aravind Kumar", "Sanjana R", "Vishal Gupta",
    "Shruthi S", "Balaji K", "Gopinath M", "Chandru S", "Ashraf Ali", "Farhan Ahmed",
    "Noor Fathima", "Aishwarya R", "Krishnan V", "Vinoth Kumar", "Saranya P",
    "Hemalatha S", "Kiran Kumar", "Nikhil Raj", "Preethi M", "Ganesh Kumar",
    "Faiz Ahmed", "Mohammed Salman", "Riya Sharma", "Lakshmi Priya",
]

ACCOUNT_TYPES = ["Savings", "Current", "Salary", "Fixed Deposit"]
TXN_TYPES = ["Deposit", "Withdrawal", "UPI", "NEFT", "IMPS", "RTGS",
             "ATM Withdrawal", "Cheque Deposit", "Cash Deposit"]
TXN_STATUS = ["Success", "Success", "Success", "Success", "Pending", "Failed"]
CUSTOMER_STATUS = ["Active", "Active", "Active", "Inactive", "Blocked"]

INTEREST_RATES = {"Savings": 3.5, "Current": 0.0, "Salary": 3.0, "Fixed Deposit": 6.75}

logging.basicConfig(
    filename=str(BASE_DIR / "system.log") if BASE_DIR.exists() else "system.log",
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)

# UTILITY FUNCTIONS

def hash_password(password: str) -> str:
    """Securely hash a password using SHA-256."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def verify_password(password: str, hashed: str) -> bool:
    return hash_password(password) == hashed


def now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def today_str() -> str:
    return datetime.now().strftime("%Y-%m-%d")


def new_uuid() -> str:
    return uuid.uuid4().hex[:10].upper()


def gen_customer_id(branch_code: str, seq: int) -> str:
    return f"CUST-{branch_code}-{seq:04d}"


def gen_employee_id(branch_code: str, seq: int) -> str:
    return f"EMP-{branch_code}-{seq:03d}"


def gen_account_number(branch_code: str, seq: int) -> str:
    return f"{branch_code}{random.randint(10, 99)}{seq:06d}"


def gen_transaction_id() -> str:
    return f"TXN{uuid.uuid4().hex[:12].upper()}"


def branch_code(branch_name: str) -> str:
    return {
        "Chennai": "CHN", "Coimbatore": "CBE", "Madurai": "MDU",
        "Salem": "SLM", "Trichy": "TRY",
    }.get(branch_name, "GEN")


def fmt_currency(amount) -> str:
    try:
        return f"₹{float(amount):,.2f}"
    except (ValueError, TypeError):
        return "₹0.00"


def safe_read_csv(path: Path) -> pd.DataFrame:
    if path.exists() and path.stat().st_size > 0:
        return pd.read_csv(path)
    return pd.DataFrame()


def write_log(log_type: str, message: str, user: str = "SYSTEM"):
    """Append an entry to the audit or activity log."""
    target = FILES["audit_log"] if log_type == "audit" else FILES["activity_log"]
    row = {"timestamp": now_str(), "user": user, "message": message}
    file_exists = target.exists() and target.stat().st_size > 0
    with open(target, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["timestamp", "user", "message"])
        if not file_exists:
            writer.writeheader()
        writer.writerow(row)
    logging.info(f"[{log_type.upper()}] {user}: {message}")

# DATABASE LAYER (CSV-BACKED)

class Database:
    """Handles creation, reading and writing of all CSV-backed tables."""

    def __init__(self):
        self._ensure_folders()
        self._ensure_files()

    @staticmethod
    def _ensure_folders():
        BASE_DIR.mkdir(parents=True, exist_ok=True)
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    def _ensure_files(self):
        schemas = {
            "branches": ["branch_id", "branch_name", "branch_code", "city",
                         "manager", "phone", "is_head_office"],
            "customers": ["customer_id", "name", "gender", "dob", "phone", "email",
                          "address", "branch", "kyc_status", "status",
                          "created_on", "customer_category"],
            "employees": ["employee_id", "name", "designation", "branch",
                          "phone", "email", "salary", "joined_on"],
            "accounts": ["account_number", "customer_id", "account_type", "branch",
                         "balance", "opened_on", "status"],
            "transactions": ["transaction_id", "account_number", "customer_id",
                              "branch", "txn_type", "amount", "balance_after",
                              "status", "datetime", "remarks", "risk_score",
                              "risk_level"],
            "login": ["username", "password_hash", "role", "linked_id",
                       "created_on", "last_login"],
            "audit_log": ["timestamp", "user", "message"],
            "activity_log": ["timestamp", "user", "message"],
            "kyc": ["customer_id", "full_name", "pan_number", "aadhaar_number",
                    "occupation", "annual_income", "document_type", "document_number",
                    "address_proof", "nominee_name", "submitted_on", "status",
                    "reviewed_by", "reviewed_on", "remarks"],
        }
        for key, cols in schemas.items():
            path = FILES[key]
            if not path.exists() or path.stat().st_size == 0:
                pd.DataFrame(columns=cols).to_csv(path, index=False)

    # generic helpers 
    def load(self, table: str) -> pd.DataFrame:
        return safe_read_csv(FILES[table])

    def save(self, table: str, df: pd.DataFrame):
        df.to_csv(FILES[table], index=False)

    def append_row(self, table: str, row: dict):
        df = self.load(table)
        df = pd.concat([df, pd.DataFrame([row])], ignore_index=True)
        self.save(table, df)

    def backup_all(self):
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        dest = BACKUP_DIR / stamp
        dest.mkdir(parents=True, exist_ok=True)
        for key, path in FILES.items():
            if path.exists():
                shutil.copy(path, dest / path.name)
        write_log("audit", f"Full backup created at {dest}")
        return dest

    def restore_latest(self):
        backups = sorted(BACKUP_DIR.glob("*"), reverse=True)
        if not backups:
            return False
        latest = backups[0]
        for file in latest.glob("*.csv"):
            shutil.copy(file, BASE_DIR / file.name)
        write_log("audit", f"Restored from backup {latest}")
        return True

# DATA GENERATOR — AUTO MASTER DATA & SAMPLE TRANSACTIONS

class DataGenerator:
    """Generates realistic Indian banking master + sample transaction data."""

    def __init__(self, db: Database):
        self.db = db

    def generate_all(self):
        self._generate_branches()
        self._generate_employees()
        self._generate_customers()
        self._generate_accounts()
        self._generate_transactions()
        self._generate_default_logins()
        write_log("audit", "Auto master data + sample data generated successfully.")

    #  branches 
    def _generate_branches(self):
        rows = []
        managers = random.sample(FIRST_NAMES_POOL, len(BRANCHES))
        for i, b in enumerate(BRANCHES):
            rows.append({
                "branch_id": f"BR{i+1:02d}",
                "branch_name": b,
                "branch_code": branch_code(b),
                "city": b,
                "manager": managers[i],
                "phone": f"044{random.randint(10000000, 99999999)}",
                "is_head_office": "Yes" if b == "Chennai" else "No",
            })
        self.db.save("branches", pd.DataFrame(rows))

    #  employees 
    def _generate_employees(self):
        designations = ["Branch Manager", "Assistant Manager", "Loan Officer",
                         "Cashier", "Teller", "Customer Relationship Officer",
                         "Operations Executive", "Compliance Officer",
                         "IT Support", "Security Officer"]
        rows = []
        for b in BRANCHES:
            code = branch_code(b)
            for seq in range(1, EMPLOYEES_PER_BRANCH + 1):
                name = random.choice(FIRST_NAMES_POOL)
                rows.append({
                    "employee_id": gen_employee_id(code, seq),
                    "name": name,
                    "designation": designations[(seq - 1) % len(designations)],
                    "branch": b,
                    "phone": f"9{random.randint(100000000, 999999999)}",
                    "email": f"{name.lower().replace(' ', '.')}{seq}@cmbbank.in",
                    "salary": random.choice([28000, 35000, 42000, 55000, 70000, 95000]),
                    "joined_on": (datetime.now() - timedelta(days=random.randint(100, 3000))).strftime("%Y-%m-%d"),
                })
        self.db.save("employees", pd.DataFrame(rows))

    #  customers 
    def _generate_customers(self):
        rows = []
        categories = ["Regular", "Premium", "Corporate", "Senior Citizen", "Student"]
        for b in BRANCHES:
            code = branch_code(b)
            for seq in range(1, CUSTOMERS_PER_BRANCH + 1):
                name = random.choice(FIRST_NAMES_POOL)
                gender = random.choice(["Male", "Female"])
                dob = datetime.now() - timedelta(days=random.randint(18 * 365, 70 * 365))
                rows.append({
                    "customer_id": gen_customer_id(code, seq),
                    "name": name,
                    "gender": gender,
                    "dob": dob.strftime("%Y-%m-%d"),
                    "phone": f"9{random.randint(100000000, 999999999)}",
                    "email": f"{name.lower().replace(' ', '.')}{seq}@gmail.com",
                    "address": f"{random.randint(1, 200)}, {random.choice(['Main Road','Gandhi Street','Anna Nagar','Market Road','Temple Street'])}, {b}",
                    "branch": b,
                    "kyc_status": random.choice(["Verified", "Verified", "Verified", "Pending"]),
                    "status": random.choice(CUSTOMER_STATUS),
                    "created_on": (datetime.now() - timedelta(days=random.randint(30, 2500))).strftime("%Y-%m-%d"),
                    "customer_category": random.choice(categories),
                })
        self.db.save("customers", pd.DataFrame(rows))

    #  accounts 
    def _generate_accounts(self):
        customers = self.db.load("customers")
        rows = []
        seq = 1
        for _, cust in customers.iterrows():
            code = branch_code(cust["branch"])
            num_accounts = random.choice([1, 1, 1, 2])
            for _ in range(num_accounts):
                acc_type = random.choice(ACCOUNT_TYPES)
                balance = round(random.uniform(1000, 500000), 2)
                rows.append({
                    "account_number": gen_account_number(code, seq),
                    "customer_id": cust["customer_id"],
                    "account_type": acc_type,
                    "branch": cust["branch"],
                    "balance": balance,
                    "opened_on": cust["created_on"],
                    "status": "Active" if cust["status"] != "Blocked" else "Blocked",
                })
                seq += 1
        self.db.save("accounts", pd.DataFrame(rows))

    #  transactions 
    def _generate_transactions(self):
        accounts = self.db.load("accounts")
        if accounts.empty:
            return
        rows = []
        acc_balance = dict(zip(accounts["account_number"], accounts["balance"]))
        acc_customer = dict(zip(accounts["account_number"], accounts["customer_id"]))
        acc_branch = dict(zip(accounts["account_number"], accounts["branch"]))
        acc_list = accounts["account_number"].tolist()

        for _ in range(TOTAL_TRANSACTIONS):
            acc = random.choice(acc_list)
            txn_type = random.choice(TXN_TYPES)
            is_credit = txn_type in ("Deposit", "Cash Deposit", "Cheque Deposit")
            amount = round(random.uniform(200, 250000), 2)
            if amount > 150000:
                amount = round(random.uniform(150000, 500000), 2)  # occasional large txn for fraud detection

            current_balance = acc_balance.get(acc, 10000)
            if is_credit:
                current_balance += amount
            else:
                if amount > current_balance:
                    amount = round(current_balance * random.uniform(0.05, 0.5), 2)
                current_balance -= amount
            acc_balance[acc] = round(current_balance, 2)

            days_ago = random.randint(0, 365)
            hour = random.choices(range(24), weights=[3]*6 + [8]*12 + [2]*6)[0]
            txn_dt = datetime.now() - timedelta(days=days_ago, hours=random.randint(0, 23))
            txn_dt = txn_dt.replace(hour=hour, minute=random.randint(0, 59))

            risk_score = self._quick_risk_score(amount, hour)
            risk_level = self._risk_level(risk_score)

            rows.append({
                "transaction_id": gen_transaction_id(),
                "account_number": acc,
                "customer_id": acc_customer.get(acc, ""),
                "branch": acc_branch.get(acc, ""),
                "txn_type": txn_type,
                "amount": amount,
                "balance_after": acc_balance[acc],
                "status": random.choice(TXN_STATUS),
                "datetime": txn_dt.strftime("%Y-%m-%d %H:%M:%S"),
                "remarks": f"{txn_type} transaction",
                "risk_score": risk_score,
                "risk_level": risk_level,
            })

        txn_df = pd.DataFrame(rows).sort_values("datetime").reset_index(drop=True)
        self.db.save("transactions", txn_df)

        # Update account balances to reflect final simulated state
        accounts["balance"] = accounts["account_number"].map(acc_balance).fillna(accounts["balance"])
        self.db.save("accounts", accounts)

    @staticmethod
    def _quick_risk_score(amount, hour) -> int:
        score = 0
        if amount > 200000:
            score += 40
        elif amount > 100000:
            score += 25
        elif amount > 50000:
            score += 10
        if hour < 6 or hour >= 23:
            score += 25
        score += random.randint(0, 15)
        return min(score, 100)

    @staticmethod
    def _risk_level(score) -> str:
        if score >= 75:
            return "Critical"
        elif score >= 50:
            return "High"
        elif score >= 25:
            return "Medium"
        return "Low"

    #  default logins 
    def _generate_default_logins(self):
        rows = [{
            "username": "admin",
            "password_hash": hash_password("admin123"),
            "role": "Admin",
            "linked_id": "ADMIN-001",
            "created_on": today_str(),
            "last_login": "",
        }]
        employees = self.db.load("employees")
        for _, emp in employees.head(5).iterrows():
            uname = emp["employee_id"].lower()
            rows.append({
                "username": uname,
                "password_hash": hash_password("emp123"),
                "role": "Employee",
                "linked_id": emp["employee_id"],
                "created_on": today_str(),
                "last_login": "",
            })
        customers = self.db.load("customers")
        for _, cust in customers.head(5).iterrows():
            uname = cust["customer_id"].lower()
            rows.append({
                "username": uname,
                "password_hash": hash_password("cust123"),
                "role": "Customer",
                "linked_id": cust["customer_id"],
                "created_on": today_str(),
                "last_login": "",
            })
        self.db.save("login", pd.DataFrame(rows))

# AUTH MANAGER

class AuthManager:
    def __init__(self, db: Database):
        self.db = db

    def login(self, username: str, password: str):
        login_df = self.db.load("login")
        if login_df.empty:
            return None
        match = login_df[login_df["username"].str.lower() == username.strip().lower()]
        if match.empty:
            return None
        row = match.iloc[0]
        if verify_password(password, row["password_hash"]):
            login_df["last_login"] = login_df["last_login"].astype("object")
            login_df.loc[login_df["username"] == row["username"], "last_login"] = now_str()
            self.db.save("login", login_df)
            write_log("audit", f"Login success for {username}", user=username)
            return {"username": row["username"], "role": row["role"], "linked_id": row["linked_id"]}
        write_log("audit", f"Failed login attempt for {username}", user=username)
        return None

    def register(self, username, password, role, linked_id):
        login_df = self.db.load("login")
        if not login_df.empty and username.lower() in login_df["username"].str.lower().values:
            return False, "Username already exists."
        new_row = {
            "username": username, "password_hash": hash_password(password),
            "role": role, "linked_id": linked_id, "created_on": today_str(), "last_login": "",
        }
        self.db.append_row("login", new_row)
        write_log("audit", f"New login registered: {username} ({role})")
        return True, "Registered successfully."

# CUSTOMER MANAGEMENT

class CustomerManager:
    def __init__(self, db: Database):
        self.db = db

    def add_customer(self, name, gender, dob, phone, email, address, branch, category="Regular"):
        customers = self.db.load("customers")
        code = branch_code(branch)
        existing = customers[customers["customer_id"].str.startswith(f"CUST-{code}-", na=False)]
        seq = len(existing) + 1
        cust_id = gen_customer_id(code, seq)
        row = {
            "customer_id": cust_id, "name": name, "gender": gender, "dob": dob,
            "phone": phone, "email": email, "address": address, "branch": branch,
            "kyc_status": "Pending", "status": "Active", "created_on": today_str(),
            "customer_category": category,
        }
        self.db.append_row("customers", row)
        write_log("audit", f"Customer added: {cust_id} ({name})")
        return cust_id

    def update_customer(self, customer_id, **fields):
        customers = self.db.load("customers")
        idx = customers.index[customers["customer_id"] == customer_id]
        if len(idx) == 0:
            return False
        for k, v in fields.items():
            if k in customers.columns and v is not None and v != "":
                customers.loc[idx, k] = v
        self.db.save("customers", customers)
        write_log("audit", f"Customer updated: {customer_id}")
        return True

    def delete_customer(self, customer_id):
        customers = self.db.load("customers")
        customers = customers[customers["customer_id"] != customer_id]
        self.db.save("customers", customers)
        write_log("audit", f"Customer deleted: {customer_id}")
        return True

    def get_customer(self, customer_id):
        customers = self.db.load("customers")
        row = customers[customers["customer_id"] == customer_id]
        return row.iloc[0].to_dict() if not row.empty else None

    def search_customers(self, keyword="", branch=None, status=None, category=None):
        customers = self.db.load("customers")
        if keyword:
            mask = (
                customers["name"].str.contains(keyword, case=False, na=False)
                | customers["customer_id"].str.contains(keyword, case=False, na=False)
                | customers["phone"].astype(str).str.contains(keyword, case=False, na=False)
                | customers["email"].str.contains(keyword, case=False, na=False)
            )
            customers = customers[mask]
        if branch and branch != "All":
            customers = customers[customers["branch"] == branch]
        if status and status != "All":
            customers = customers[customers["status"] == status]
        if category and category != "All":
            customers = customers[customers["customer_category"] == category]
        return customers

# KYC MANAGEMENT

class KYCManager:
    """
    Handles manual KYC submission by the customer and manual approval by the
    Admin/Employee side. A customer's overall KYC status only moves to
    'Verified' once an authorised staff member reviews and approves the
    submitted KYC form. Not every customer is pending — only those who have
    not yet completed / been approved show up in the pending queue.
    """

    def __init__(self, db: Database):
        self.db = db

    def get_kyc(self, customer_id):
        kyc_df = self.db.load("kyc")
        if kyc_df.empty:
            return None
        row = kyc_df[kyc_df["customer_id"] == customer_id]
        return row.iloc[0].to_dict() if not row.empty else None

    def submit_kyc(self, customer_id, full_name, pan_number, aadhaar_number,
                    occupation, annual_income, document_type, document_number,
                    address_proof, nominee_name):
        """Customer manually fills and submits their KYC form (status -> Pending)."""
        kyc_df = self.db.load("kyc")
        row = {
            "customer_id": customer_id, "full_name": full_name, "pan_number": pan_number,
            "aadhaar_number": aadhaar_number, "occupation": occupation,
            "annual_income": annual_income, "document_type": document_type,
            "document_number": document_number, "address_proof": address_proof,
            "nominee_name": nominee_name, "submitted_on": today_str(),
            "status": "Pending", "reviewed_by": "", "reviewed_on": "", "remarks": "",
        }
        if not kyc_df.empty and customer_id in kyc_df["customer_id"].values:
            kyc_df = kyc_df[kyc_df["customer_id"] != customer_id]  # replace any prior submission
        kyc_df = pd.concat([kyc_df, pd.DataFrame([row])], ignore_index=True)
        self.db.save("kyc", kyc_df)

        # Reflect "submission made, awaiting review" on the customer record too
        customers = self.db.load("customers")
        idx = customers.index[customers["customer_id"] == customer_id]
        if len(idx) > 0:
            customers.loc[idx, "kyc_status"] = "Pending"
            self.db.save("customers", customers)

        write_log("audit", f"KYC submitted by customer {customer_id}, awaiting admin approval.")

    def pending_queue(self):
        """Only customers with an actual submitted-and-unreviewed KYC form."""
        kyc_df = self.db.load("kyc")
        if kyc_df.empty:
            return kyc_df
        return kyc_df[kyc_df["status"] == "Pending"]

    def approve(self, customer_id, reviewer_username, remarks="KYC verified and approved."):
        kyc_df = self.db.load("kyc")
        idx = kyc_df.index[kyc_df["customer_id"] == customer_id]
        if len(idx) == 0:
            return False, "No KYC submission found for this customer."
        kyc_df["status"] = kyc_df["status"].astype("object")
        kyc_df["reviewed_by"] = kyc_df["reviewed_by"].astype("object")
        kyc_df["reviewed_on"] = kyc_df["reviewed_on"].astype("object")
        kyc_df["remarks"] = kyc_df["remarks"].astype("object")
        kyc_df.loc[idx, "status"] = "Approved"
        kyc_df.loc[idx, "reviewed_by"] = reviewer_username
        kyc_df.loc[idx, "reviewed_on"] = now_str()
        kyc_df.loc[idx, "remarks"] = remarks
        self.db.save("kyc", kyc_df)

        customers = self.db.load("customers")
        cidx = customers.index[customers["customer_id"] == customer_id]
        if len(cidx) > 0:
            customers.loc[cidx, "kyc_status"] = "Verified"
            self.db.save("customers", customers)

        write_log("audit", f"KYC approved for {customer_id} by {reviewer_username}", user=reviewer_username)
        return True, "KYC approved successfully."

    def reject(self, customer_id, reviewer_username, remarks="KYC documents insufficient / incorrect."):
        kyc_df = self.db.load("kyc")
        idx = kyc_df.index[kyc_df["customer_id"] == customer_id]
        if len(idx) == 0:
            return False, "No KYC submission found for this customer."
        kyc_df["status"] = kyc_df["status"].astype("object")
        kyc_df["reviewed_by"] = kyc_df["reviewed_by"].astype("object")
        kyc_df["reviewed_on"] = kyc_df["reviewed_on"].astype("object")
        kyc_df["remarks"] = kyc_df["remarks"].astype("object")
        kyc_df.loc[idx, "status"] = "Rejected"
        kyc_df.loc[idx, "reviewed_by"] = reviewer_username
        kyc_df.loc[idx, "reviewed_on"] = now_str()
        kyc_df.loc[idx, "remarks"] = remarks
        self.db.save("kyc", kyc_df)

        customers = self.db.load("customers")
        cidx = customers.index[customers["customer_id"] == customer_id]
        if len(cidx) > 0:
            customers.loc[cidx, "kyc_status"] = "Pending"
            self.db.save("customers", customers)

        write_log("audit", f"KYC rejected for {customer_id} by {reviewer_username}", user=reviewer_username)
        return True, "KYC rejected. Customer must resubmit."

# ACCOUNT MANAGEMENT

class AccountManager:
    def __init__(self, db: Database):
        self.db = db

    def open_account(self, customer_id, account_type, branch, initial_deposit=0.0):
        accounts = self.db.load("accounts")
        code = branch_code(branch)
        seq = len(accounts) + 1
        acc_num = gen_account_number(code, seq)
        row = {
            "account_number": acc_num, "customer_id": customer_id, "account_type": account_type,
            "branch": branch, "balance": round(float(initial_deposit), 2),
            "opened_on": today_str(), "status": "Active",
        }
        self.db.append_row("accounts", row)
        write_log("audit", f"Account opened: {acc_num} for {customer_id}")
        return acc_num

    def get_account(self, account_number):
        accounts = self.db.load("accounts")
        row = accounts[accounts["account_number"] == account_number]
        return row.iloc[0].to_dict() if not row.empty else None

    def get_accounts_by_customer(self, customer_id):
        accounts = self.db.load("accounts")
        return accounts[accounts["customer_id"] == customer_id]

    def update_balance(self, account_number, new_balance):
        accounts = self.db.load("accounts")
        idx = accounts.index[accounts["account_number"] == account_number]
        if len(idx) == 0:
            return False
        accounts.loc[idx, "balance"] = round(float(new_balance), 2)
        self.db.save("accounts", accounts)
        return True

    def calculate_interest(self, account_number):
        acc = self.get_account(account_number)
        if not acc:
            return 0.0
        rate = INTEREST_RATES.get(acc["account_type"], 0.0)
        return round(float(acc["balance"]) * rate / 100, 2)

# TRANSACTION MANAGEMENT

class TransactionManager:
    def __init__(self, db: Database, account_mgr: AccountManager):
        self.db = db
        self.acc_mgr = account_mgr

    def _record(self, account_number, customer_id, branch, txn_type, amount, balance_after, status, remarks):
        risk_score, risk_level = FraudDetectionEngine.score_single(amount, datetime.now().hour)
        row = {
            "transaction_id": gen_transaction_id(), "account_number": account_number,
            "customer_id": customer_id, "branch": branch, "txn_type": txn_type,
            "amount": round(float(amount), 2), "balance_after": round(float(balance_after), 2),
            "status": status, "datetime": now_str(), "remarks": remarks,
            "risk_score": risk_score, "risk_level": risk_level,
        }
        self.db.append_row("transactions", row)
        write_log("activity", f"{txn_type} of {fmt_currency(amount)} on {account_number}")
        return row["transaction_id"]

    def deposit(self, account_number, amount, txn_type="Deposit", remarks="Cash Deposit"):
        acc = self.acc_mgr.get_account(account_number)
        if not acc:
            return False, "Account not found."
        new_balance = float(acc["balance"]) + float(amount)
        self.acc_mgr.update_balance(account_number, new_balance)
        txn_id = self._record(account_number, acc["customer_id"], acc["branch"],
                               txn_type, amount, new_balance, "Success", remarks)
        return True, txn_id

    def withdraw(self, account_number, amount, txn_type="Withdrawal", remarks="Cash Withdrawal"):
        acc = self.acc_mgr.get_account(account_number)
        if not acc:
            return False, "Account not found."
        if float(acc["balance"]) < float(amount):
            self._record(account_number, acc["customer_id"], acc["branch"],
                          txn_type, amount, acc["balance"], "Failed", "Insufficient funds")
            return False, "Insufficient balance."
        new_balance = float(acc["balance"]) - float(amount)
        self.acc_mgr.update_balance(account_number, new_balance)
        txn_id = self._record(account_number, acc["customer_id"], acc["branch"],
                               txn_type, amount, new_balance, "Success", remarks)
        return True, txn_id

    def transfer(self, from_account, to_account, amount, txn_type="NEFT"):
        ok, msg = self.withdraw(from_account, amount, txn_type, f"Transfer to {to_account}")
        if not ok:
            return False, msg
        ok2, msg2 = self.deposit(to_account, amount, txn_type, f"Transfer from {from_account}")
        return ok2, msg2

    def mini_statement(self, account_number, n=10):
        txns = self.db.load("transactions")
        txns = txns[txns["account_number"] == account_number].sort_values("datetime", ascending=False)
        return txns.head(n)

    def get_history(self, customer_id=None, branch=None, month=None, year=None,
                     min_amount=None, max_amount=None, status=None):
        txns = self.db.load("transactions")
        if txns.empty:
            return txns
        txns["datetime"] = pd.to_datetime(txns["datetime"], errors="coerce")
        if customer_id:
            txns = txns[txns["customer_id"] == customer_id]
        if branch and branch != "All":
            txns = txns[txns["branch"] == branch]
        if month and month != "All":
            txns = txns[txns["datetime"].dt.month == int(month)]
        if year and year != "All":
            txns = txns[txns["datetime"].dt.year == int(year)]
        if min_amount is not None:
            txns = txns[txns["amount"] >= min_amount]
        if max_amount is not None:
            txns = txns[txns["amount"] <= max_amount]
        if status and status != "All":
            txns = txns[txns["status"] == status]
        return txns.sort_values("datetime", ascending=False)

# FRAUD DETECTION ENGINE

class FraudDetectionEngine:
    """Rule based fraud / risk scoring engine."""

    LARGE_TXN_THRESHOLD = 150000
    RAPID_TXN_WINDOW_MIN = 10
    RAPID_TXN_COUNT = 3
    MULTI_WITHDRAW_COUNT = 4
    NIGHT_START, NIGHT_END = 23, 6

    def __init__(self, db: Database):
        self.db = db

    @staticmethod
    def score_single(amount, hour):
        score = 0
        if amount > 300000:
            score += 45
        elif amount > FraudDetectionEngine.LARGE_TXN_THRESHOLD:
            score += 30
        elif amount > 75000:
            score += 15
        if hour >= FraudDetectionEngine.NIGHT_START or hour < FraudDetectionEngine.NIGHT_END:
            score += 20
        score = min(score, 100)
        level = "Critical" if score >= 75 else "High" if score >= 50 else "Medium" if score >= 25 else "Low"
        return score, level

    def analyze(self) -> pd.DataFrame:
        """Run full fraud analysis across all transactions, return flagged records."""
        txns = self.db.load("transactions")
        if txns.empty:
            return txns
        txns["datetime"] = pd.to_datetime(txns["datetime"], errors="coerce")
        flags = []

        for acc, group in txns.groupby("account_number"):
            group = group.sort_values("datetime")
            withdrawals = group[group["txn_type"].str.contains("Withdrawal", case=False, na=False)]
            transfers = group[group["txn_type"].isin(["NEFT", "IMPS", "RTGS", "UPI"])]

            # Large transactions
            large = group[group["amount"] > self.LARGE_TXN_THRESHOLD]
            for _, r in large.iterrows():
                flags.append((r["transaction_id"], acc, "Large Transaction"))

            # Multiple withdrawals in a day
            if not withdrawals.empty:
                daily_counts = withdrawals.groupby(withdrawals["datetime"].dt.date).size()
                bad_days = daily_counts[daily_counts >= self.MULTI_WITHDRAW_COUNT]
                for d in bad_days.index:
                    ids = withdrawals[withdrawals["datetime"].dt.date == d]["transaction_id"].tolist()
                    for tid in ids:
                        flags.append((tid, acc, "Multiple Withdrawals"))

            # Multiple transfers in a day
            if not transfers.empty:
                daily_counts = transfers.groupby(transfers["datetime"].dt.date).size()
                bad_days = daily_counts[daily_counts >= self.MULTI_WITHDRAW_COUNT]
                for d in bad_days.index:
                    ids = transfers[transfers["datetime"].dt.date == d]["transaction_id"].tolist()
                    for tid in ids:
                        flags.append((tid, acc, "Multiple Transfers"))

            # Night transactions
            night = group[(group["datetime"].dt.hour >= self.NIGHT_START) | (group["datetime"].dt.hour < self.NIGHT_END)]
            for _, r in night.iterrows():
                flags.append((r["transaction_id"], acc, "Night Transaction"))

            # Rapid transactions (many txns within short window)
            times = group["datetime"].tolist()
            ids = group["transaction_id"].tolist()
            for i in range(len(times)):
                window_ids = [ids[i]]
                for j in range(i + 1, len(times)):
                    if (times[j] - times[i]).total_seconds() <= self.RAPID_TXN_WINDOW_MIN * 60:
                        window_ids.append(ids[j])
                    else:
                        break
                if len(window_ids) >= self.RAPID_TXN_COUNT:
                    for tid in window_ids:
                        flags.append((tid, acc, "Rapid Transactions"))

            # Duplicate transfers (same amount within same day)
            if not transfers.empty:
                dup = transfers.groupby([transfers["datetime"].dt.date, "amount"]).size()
                dup = dup[dup > 1]
                for (d, amt) in dup.index:
                    ids2 = transfers[(transfers["datetime"].dt.date == d) & (transfers["amount"] == amt)]["transaction_id"].tolist()
                    for tid in ids2:
                        flags.append((tid, acc, "Duplicate Transfer"))

        flag_map = defaultdict(list)
        for tid, acc, reason in flags:
            flag_map[tid].append(reason)

        txns["fraud_reasons"] = txns["transaction_id"].map(lambda t: ", ".join(sorted(set(flag_map.get(t, [])))))
        txns["is_suspicious"] = txns["fraud_reasons"].apply(lambda x: len(x) > 0)
        return txns[txns["is_suspicious"]].sort_values("risk_score", ascending=False)

    def suspicious_report(self):
        flagged = self.analyze()
        if flagged.empty:
            return flagged
        return flagged[["transaction_id", "account_number", "customer_id", "branch",
                         "txn_type", "amount", "datetime", "risk_score", "risk_level",
                         "fraud_reasons"]]

# REPORT ENGINE

class ReportEngine:
    def __init__(self, db: Database):
        self.db = db

    def customer_activity_report(self, customer_id):
        customers = self.db.load("customers")
        accounts = self.db.load("accounts")
        txns = self.db.load("transactions")

        cust_row = customers[customers["customer_id"] == customer_id]
        if cust_row.empty:
            return None
        cust = cust_row.iloc[0].to_dict()

        cust_accounts = accounts[accounts["customer_id"] == customer_id]
        cust_txns = txns[txns["customer_id"] == customer_id].copy()
        if not cust_txns.empty:
            cust_txns["datetime"] = pd.to_datetime(cust_txns["datetime"], errors="coerce")

        total_balance = cust_accounts["balance"].sum() if not cust_accounts.empty else 0
        deposits = cust_txns[cust_txns["txn_type"].isin(["Deposit", "Cash Deposit", "Cheque Deposit"])] if not cust_txns.empty else pd.DataFrame()
        withdrawals = cust_txns[cust_txns["txn_type"].str.contains("Withdrawal", case=False, na=False)] if not cust_txns.empty else pd.DataFrame()

        highest_deposit = deposits["amount"].max() if not deposits.empty else 0
        highest_withdrawal = withdrawals["amount"].max() if not withdrawals.empty else 0
        avg_txn = cust_txns["amount"].mean() if not cust_txns.empty else 0
        risk_score = cust_txns["risk_score"].mean() if not cust_txns.empty else 0

        monthly_activity = pd.DataFrame()
        if not cust_txns.empty:
            monthly_activity = cust_txns.groupby(cust_txns["datetime"].dt.strftime("%Y-%m")).agg(
                total_amount=("amount", "sum"), txn_count=("transaction_id", "count")
            ).reset_index().rename(columns={"datetime": "month"})

        health = "Excellent" if total_balance > 200000 else "Good" if total_balance > 50000 else "Fair" if total_balance > 10000 else "Needs Attention"
        recommendation = self._recommendation(cust, total_balance, risk_score)

        return {
            "customer": cust,
            "accounts": cust_accounts,
            "transactions": cust_txns.sort_values("datetime", ascending=False) if not cust_txns.empty else cust_txns,
            "total_balance": round(float(total_balance), 2),
            "highest_deposit": round(float(highest_deposit), 2),
            "highest_withdrawal": round(float(highest_withdrawal), 2),
            "average_transaction": round(float(avg_txn), 2),
            "monthly_activity": monthly_activity,
            "risk_score": round(float(risk_score), 2),
            "account_health": health,
            "recommendation": recommendation,
            "total_transactions": len(cust_txns),
            "last_transaction": cust_txns["datetime"].max() if not cust_txns.empty else None,
        }

    @staticmethod
    def _recommendation(cust, balance, risk_score):
        notes = []
        if cust.get("kyc_status") != "Verified":
            notes.append("Complete KYC verification immediately.")
        if risk_score and risk_score >= 50:
            notes.append("Elevated risk activity detected — recommend manual review.")
        if balance < 5000:
            notes.append("Encourage minimum balance maintenance / savings plan.")
        if not notes:
            notes.append("Account in good standing. Consider premium banking offers.")
        return " ".join(notes)

    def monthly_transaction_report(self, year=None):
        txns = self.db.load("transactions")
        if txns.empty:
            return pd.DataFrame()
        txns["datetime"] = pd.to_datetime(txns["datetime"], errors="coerce")
        if year and year != "All":
            txns = txns[txns["datetime"].dt.year == int(year)]
        return txns.groupby(txns["datetime"].dt.strftime("%Y-%m")).agg(
            total_amount=("amount", "sum"), txn_count=("transaction_id", "count"),
            avg_amount=("amount", "mean")
        ).reset_index().rename(columns={"datetime": "month"})

    def branch_report(self):
        txns = self.db.load("transactions")
        customers = self.db.load("customers")
        if txns.empty:
            return pd.DataFrame(), pd.DataFrame()
        deposits = txns[txns["txn_type"].isin(["Deposit", "Cash Deposit", "Cheque Deposit"])]
        withdrawals = txns[txns["txn_type"].str.contains("Withdrawal", case=False, na=False)]
        dep_summary = deposits.groupby("branch")["amount"].sum().reset_index(name="total_deposits")
        wd_summary = withdrawals.groupby("branch")["amount"].sum().reset_index(name="total_withdrawals")
        cust_summary = customers.groupby("branch").size().reset_index(name="total_customers")
        merged = dep_summary.merge(wd_summary, on="branch", how="outer").merge(cust_summary, on="branch", how="outer").fillna(0)
        return merged, txns.groupby("branch").size().reset_index(name="total_transactions")

    def top_customers(self, n=10, by="deposit"):
        txns = self.db.load("transactions")
        customers = self.db.load("customers")
        if txns.empty:
            return pd.DataFrame()
        if by == "deposit":
            subset = txns[txns["txn_type"].isin(["Deposit", "Cash Deposit", "Cheque Deposit"])]
        else:
            subset = txns[txns["txn_type"].str.contains("Withdrawal", case=False, na=False)]
        summary = subset.groupby("customer_id")["amount"].sum().reset_index(name="total_amount")
        summary = summary.merge(customers[["customer_id", "name", "branch"]], on="customer_id", how="left")
        return summary.sort_values("total_amount", ascending=False).head(n)

    def employee_report(self):
        return self.db.load("employees")

# CHART ENGINE

class ChartEngine:
    """Generates professional Plotly charts for the dashboard."""

    COLORWAY = ["#0B3D91", "#1E88E5", "#42A5F5", "#90CAF9", "#0D47A1", "#64B5F6"]

    @staticmethod
    def monthly_trend(txns: pd.DataFrame):
        if txns.empty:
            return go.Figure()
        d = txns.copy()
        d["datetime"] = pd.to_datetime(d["datetime"], errors="coerce")
        monthly = d.groupby(d["datetime"].dt.strftime("%Y-%m"))["amount"].sum().reset_index()
        fig = px.line(monthly, x="datetime", y="amount", markers=True,
                      title="Monthly Transaction Trend", color_discrete_sequence=["#0B3D91"])
        fig.update_layout(xaxis_title="Month", yaxis_title="Total Amount (₹)")
        return fig

    @staticmethod
    def branch_customers(customers: pd.DataFrame):
        if customers.empty:
            return go.Figure()
        counts = customers.groupby("branch").size().reset_index(name="count")
        fig = px.bar(counts, x="branch", y="count", title="Branch-wise Customers",
                     color="branch", color_discrete_sequence=ChartEngine.COLORWAY)
        return fig

    @staticmethod
    def txn_type_distribution(txns: pd.DataFrame):
        if txns.empty:
            return go.Figure()
        counts = txns["txn_type"].value_counts().reset_index()
        counts.columns = ["txn_type", "count"]
        fig = px.pie(counts, names="txn_type", values="count", title="Transaction Type Distribution",
                     color_discrete_sequence=ChartEngine.COLORWAY, hole=0.4)
        return fig

    @staticmethod
    def deposit_vs_withdrawal(txns: pd.DataFrame):
        if txns.empty:
            return go.Figure()
        deposits = txns[txns["txn_type"].isin(["Deposit", "Cash Deposit", "Cheque Deposit"])]["amount"].sum()
        withdrawals = txns[txns["txn_type"].str.contains("Withdrawal", case=False, na=False)]["amount"].sum()
        fig = px.bar(x=["Deposits", "Withdrawals"], y=[deposits, withdrawals],
                     title="Deposit vs Withdrawal", color=["Deposits", "Withdrawals"],
                     color_discrete_sequence=["#1E88E5", "#0B3D91"])
        fig.update_layout(showlegend=False, xaxis_title="", yaxis_title="Amount (₹)")
        return fig

    @staticmethod
    def fraud_risk_distribution(txns: pd.DataFrame):
        if txns.empty:
            return go.Figure()
        counts = txns["risk_level"].value_counts().reindex(["Low", "Medium", "High", "Critical"]).fillna(0).reset_index()
        counts.columns = ["risk_level", "count"]
        fig = px.bar(counts, x="risk_level", y="count", title="Fraud Risk Distribution",
                     color="risk_level",
                     color_discrete_map={"Low": "#4CAF50", "Medium": "#FFC107", "High": "#FF7043", "Critical": "#D32F2F"})
        return fig

    @staticmethod
    def customer_activity_analysis(txns: pd.DataFrame):
        if txns.empty:
            return go.Figure()
        d = txns.copy()
        d["datetime"] = pd.to_datetime(d["datetime"], errors="coerce")
        activity = d.groupby("customer_id").size().reset_index(name="txn_count")
        fig = px.histogram(activity, x="txn_count", nbins=30, title="Customer Activity Analysis",
                           color_discrete_sequence=["#0B3D91"])
        fig.update_layout(xaxis_title="Transactions per Customer", yaxis_title="Number of Customers")
        return fig

    @staticmethod
    def balance_distribution(accounts: pd.DataFrame):
        if accounts.empty:
            return go.Figure()
        fig = px.histogram(accounts, x="balance", nbins=40, title="Balance Distribution",
                           color_discrete_sequence=["#1E88E5"])
        return fig

    @staticmethod
    def branch_performance(branch_summary: pd.DataFrame):
        if branch_summary.empty:
            return go.Figure()
        fig = go.Figure()
        fig.add_trace(go.Bar(x=branch_summary["branch"], y=branch_summary["total_deposits"],
                              name="Deposits", marker_color="#1E88E5"))
        fig.add_trace(go.Bar(x=branch_summary["branch"], y=branch_summary["total_withdrawals"],
                              name="Withdrawals", marker_color="#0B3D91"))
        fig.update_layout(barmode="group", title="Branch Performance")
        return fig

    @staticmethod
    def employee_performance(employees: pd.DataFrame):
        if employees.empty:
            return go.Figure()
        counts = employees.groupby("branch").size().reset_index(name="count")
        fig = px.bar(counts, x="branch", y="count", title="Employee Performance / Distribution",
                     color_discrete_sequence=ChartEngine.COLORWAY)
        return fig

# STREAMLIT UI — STYLING

CUSTOM_CSS = """
<style>
:root {
    --dark-blue: #0B3D91;
    --sky-blue: #1E88E5;
    --light-blue: #E3F2FD;
}
.stApp { background-color: #F4F8FC; }
[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #0B3D91 0%, #123B7A 100%);
}
[data-testid="stSidebar"] * { color: #FFFFFF !important; }
.main-header {
    background: linear-gradient(90deg, #0B3D91, #1E88E5);
    padding: 22px 30px; border-radius: 14px; color: white;
    margin-bottom: 20px; box-shadow: 0 4px 14px rgba(11,61,145,0.25);
}
.main-header h1 { margin: 0; font-size: 28px; }
.main-header p { margin: 4px 0 0 0; opacity: 0.9; }
.kpi-card {
    background: white; border-radius: 14px; padding: 18px 20px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.08); border-left: 6px solid #1E88E5;
    text-align: center;
}
.kpi-card h2 { margin: 0; color: #0B3D91; font-size: 26px; }
.kpi-card p { margin: 4px 0 0 0; color: #555; font-size: 13px; font-weight: 600; }
.section-card {
    background: white; border-radius: 14px; padding: 20px; margin-bottom: 16px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.06);
}
.footer-bar {
    text-align: center; padding: 14px; color: #0B3D91; font-size: 13px;
    margin-top: 30px; border-top: 1px solid #cdddf0;
}
.badge-active { background:#C8E6C9; color:#256029; padding:3px 10px; border-radius:10px; font-size:12px; font-weight:600;}
.badge-inactive { background:#FFE0B2; color:#8A5300; padding:3px 10px; border-radius:10px; font-size:12px; font-weight:600;}
.badge-blocked { background:#FFCDD2; color:#B71C1C; padding:3px 10px; border-radius:10px; font-size:12px; font-weight:600;}
</style>
"""


def render_header(subtitle="Professional Banking Transaction Analysis System"):
    st.markdown(CUSTOM_CSS, unsafe_allow_html=True)
    st.markdown(f"""
    <div class="main-header">
        <h1>🏦 Chennai Metropolitan Bank</h1>
        <p>{subtitle} &nbsp;|&nbsp; Head Office: Chennai &nbsp;|&nbsp; Branches: Chennai, Coimbatore, Madurai, Salem, Trichy</p>
    </div>
    """, unsafe_allow_html=True)


def render_footer():
    st.markdown(f"""
    <div class="footer-bar">
        © {datetime.now().year} Chennai Metropolitan Bank — Banking Transaction Analysis System |
        Head Office: Chennai | Secure • Reliable • Professional
    </div>
    """, unsafe_allow_html=True)


def kpi_card(col, label, value, icon=""):
    col.markdown(f"""
    <div class="kpi-card">
        <h2>{icon} {value}</h2>
        <p>{label}</p>
    </div>
    """, unsafe_allow_html=True)


def status_badge(status):
    cls = {"Active": "badge-active", "Inactive": "badge-inactive", "Blocked": "badge-blocked"}.get(status, "badge-inactive")
    return f'<span class="{cls}">{status}</span>'

# STREAMLIT APPLICATION

class BankingApp:
    def __init__(self):
        self.db = Database()
        if self.db.load("customers").empty:
            with st.spinner("Initializing bank database with auto-generated master data..."):
                DataGenerator(self.db).generate_all()

        self.auth = AuthManager(self.db)
        self.cust_mgr = CustomerManager(self.db)
        self.kyc_mgr = KYCManager(self.db)
        self.acc_mgr = AccountManager(self.db)
        self.txn_mgr = TransactionManager(self.db, self.acc_mgr)
        self.fraud_engine = FraudDetectionEngine(self.db)
        self.report_engine = ReportEngine(self.db)

        self._init_session()

    @staticmethod
    def _init_session():
        defaults = {"logged_in": False, "user": None, "menu": "Dashboard"}
        for k, v in defaults.items():
            if k not in st.session_state:
                st.session_state[k] = v

    #  run
    def run(self):
        if not st.session_state.logged_in:
            self._login_page()
        else:
            self._main_app()

    # login
    def _login_page(self):
        st.markdown(CUSTOM_CSS, unsafe_allow_html=True)
        st.markdown("""
        <div class="main-header" style="text-align:center;">
            <h1>🏦 Chennai Metropolitan Bank</h1>
            <p>Banking Transaction Analysis System — Secure Login Portal</p>
        </div>
        """, unsafe_allow_html=True)

        col1, col2, col3 = st.columns([1, 1.2, 1])
        with col2:
            st.markdown('<div class="section-card">', unsafe_allow_html=True)
            st.subheader("🔐 Login to your account")
            role = st.selectbox("Login As", ["Admin", "Employee", "Customer"])
            username = st.text_input("Username", placeholder="e.g. admin / emp-chn-001 / cust-chn-0001")
            password = st.text_input("Password", type="password")
            colA, colB = st.columns(2)
            login_btn = colA.button("🔓 Login", use_container_width=True)
            demo_btn = colB.button("ℹ️ Demo Credentials", use_container_width=True)

            if demo_btn:
                st.info("**Admin:** admin / admin123\n\n**Employee:** any emp-xxx-### id (lowercase) / emp123\n\n**Customer:** any cust-xxx-#### id (lowercase) / cust123")

            if login_btn:
                result = self.auth.login(username, password)
                if result and result["role"] == role:
                    st.session_state.logged_in = True
                    st.session_state.user = result
                    st.success(f"Welcome, {username}! Redirecting...")
                    time.sleep(0.6)
                    st.rerun()
                elif result:
                    st.error(f"This account is registered as '{result['role']}', not '{role}'.")
                else:
                    st.error("Invalid username or password.")
            st.markdown('</div>', unsafe_allow_html=True)
        render_footer()

    # main
    def _main_app(self):
        user = st.session_state.user
        st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

        with st.sidebar:
            st.markdown("## 🏦 CMB Bank")
            st.markdown(f"**User:** {user['username']}")
            st.markdown(f"**Role:** {user['role']}")
            st.markdown("---")

            menu_options = ["Dashboard"]
            if user["role"] in ("Admin", "Employee"):
                menu_options += ["Customer Management", "KYC Approval", "Account Management", "Transactions",
                                  "Fraud Detection", "Reports", "Backup & Logs"]
            else:
                menu_options += ["My Accounts", "My Transactions", "KYC Verification", "My Activity Report"]

            choice = st.radio("📋 Navigation", menu_options, label_visibility="collapsed")
            st.session_state.menu = choice

            st.markdown("---")
            if st.button("🚪 Logout", use_container_width=True):
                write_log("audit", f"Logout: {user['username']}", user=user["username"])
                st.session_state.logged_in = False
                st.session_state.user = None
                st.rerun()

        render_header()

        menu = st.session_state.menu
        if menu == "Dashboard":
            self._page_dashboard()
        elif menu == "Customer Management":
            self._page_customer_management()
        elif menu == "KYC Approval":
            self._page_kyc_approval()
        elif menu == "Account Management":
            self._page_account_management()
        elif menu == "Transactions":
            self._page_transactions()
        elif menu == "Fraud Detection":
            self._page_fraud_detection()
        elif menu == "Reports":
            self._page_reports()
        elif menu == "Backup & Logs":
            self._page_backup_logs()
        elif menu == "My Accounts":
            self._page_my_accounts()
        elif menu == "My Transactions":
            self._page_my_transactions()
        elif menu == "KYC Verification":
            self._page_my_kyc()
        elif menu == "My Activity Report":
            self._page_my_activity_report()

        render_footer()

    #  DASHBOARD
    def _page_dashboard(self):
        customers = self.db.load("customers")
        employees = self.db.load("employees")
        accounts = self.db.load("accounts")
        txns = self.db.load("transactions")

        st.subheader("📊 Executive Dashboard")

        today_txns = txns[txns["datetime"].astype(str).str.startswith(today_str())] if not txns.empty else pd.DataFrame()
        deposits_total = txns[txns["txn_type"].isin(["Deposit", "Cash Deposit", "Cheque Deposit"])]["amount"].sum() if not txns.empty else 0
        withdrawals_total = txns[txns["txn_type"].str.contains("Withdrawal", case=False, na=False)]["amount"].sum() if not txns.empty else 0
        fraud_alerts = len(txns[txns["risk_level"].isin(["High", "Critical"])]) if not txns.empty else 0

        c1, c2, c3, c4 = st.columns(4)
        kpi_card(c1, "Total Customers", len(customers), "👥")
        kpi_card(c2, "Total Employees", len(employees), "🧑‍💼")
        kpi_card(c3, "Total Accounts", len(accounts), "💳")
        kpi_card(c4, "Today's Transactions", len(today_txns), "🔄")

        c5, c6, c7, c8 = st.columns(4)
        kpi_card(c5, "Total Deposits", fmt_currency(deposits_total), "💰")
        kpi_card(c6, "Total Withdrawals", fmt_currency(withdrawals_total), "💸")
        kpi_card(c7, "Current Balance (All)", fmt_currency(accounts["balance"].sum() if not accounts.empty else 0), "🏦")
        kpi_card(c8, "Fraud Alerts", fraud_alerts, "🚨")

        st.markdown("###")
        st.markdown('<div class="section-card">', unsafe_allow_html=True)
        st.markdown("### 📈 Analytics Overview")
        col1, col2 = st.columns(2)
        col1.plotly_chart(ChartEngine.monthly_trend(txns), use_container_width=True)
        col2.plotly_chart(ChartEngine.branch_customers(customers), use_container_width=True)

        col3, col4 = st.columns(2)
        col3.plotly_chart(ChartEngine.txn_type_distribution(txns), use_container_width=True)
        col4.plotly_chart(ChartEngine.deposit_vs_withdrawal(txns), use_container_width=True)

        col5, col6 = st.columns(2)
        col5.plotly_chart(ChartEngine.fraud_risk_distribution(txns), use_container_width=True)
        col6.plotly_chart(ChartEngine.customer_activity_analysis(txns), use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)

    # CUSTOMERS
    def _page_customer_management(self):
        st.subheader("👥 Customer Management")
        tabs = st.tabs(["➕ Add Customer", "🔍 Search / View", "✏️ Update", "🗑️ Delete", "📋 All Customers"])

        with tabs[0]:
            with st.form("add_customer_form"):
                col1, col2 = st.columns(2)
                name = col1.text_input("Full Name")
                gender = col2.selectbox("Gender", ["Male", "Female"])
                dob = col1.date_input("Date of Birth", min_value=datetime(1940, 1, 1))
                phone = col2.text_input("Phone Number")
                email = col1.text_input("Email")
                branch = col2.selectbox("Branch", BRANCHES)
                address = st.text_area("Address")
                category = st.selectbox("Customer Category", ["Regular", "Premium", "Corporate", "Senior Citizen", "Student"])
                submitted = st.form_submit_button("✅ Add Customer", use_container_width=True)
                if submitted:
                    if not name or not phone:
                        st.error("Name and phone are required.")
                    else:
                        cust_id = self.cust_mgr.add_customer(name, gender, str(dob), phone, email, address, branch, category)
                        st.success(f"Customer added successfully! Customer ID: **{cust_id}**")

        with tabs[1]:
            keyword = st.text_input("Search by Name / ID / Phone / Email")
            colf1, colf2, colf3 = st.columns(3)
            branch_f = colf1.selectbox("Branch Filter", ["All"] + BRANCHES)
            status_f = colf2.selectbox("Status Filter", ["All"] + CUSTOMER_STATUS)
            cat_f = colf3.selectbox("Category Filter", ["All", "Regular", "Premium", "Corporate", "Senior Citizen", "Student"])
            results = self.cust_mgr.search_customers(keyword, branch_f, status_f, cat_f)
            st.write(f"**{len(results)}** customer(s) found.")
            st.dataframe(results, use_container_width=True, height=350)

            if not results.empty:
                sel = st.selectbox("View Full Profile", results["customer_id"].tolist())
                if sel:
                    cust = self.cust_mgr.get_customer(sel)
                    accs = self.acc_mgr.get_accounts_by_customer(sel)
                    st.markdown('<div class="section-card">', unsafe_allow_html=True)
                    st.markdown(f"#### {cust['name']} — `{cust['customer_id']}`")
                    c1, c2, c3 = st.columns(3)
                    c1.write(f"**Branch:** {cust['branch']}")
                    c2.write(f"**Phone:** {cust['phone']}")
                    c3.write(f"**Email:** {cust['email']}")
                    c1.write(f"**KYC Status:** {cust['kyc_status']}")
                    c2.markdown(f"**Status:** {status_badge(cust['status'])}", unsafe_allow_html=True)
                    c3.write(f"**Category:** {cust['customer_category']}")
                    st.write("**Accounts:**")
                    st.dataframe(accs, use_container_width=True)
                    st.markdown('</div>', unsafe_allow_html=True)

        with tabs[2]:
            customers = self.db.load("customers")
            cust_id = st.selectbox("Select Customer to Update", customers["customer_id"].tolist(), key="upd_sel")
            if cust_id:
                cust = self.cust_mgr.get_customer(cust_id)
                with st.form("update_form"):
                    col1, col2 = st.columns(2)
                    phone = col1.text_input("Phone", value=cust["phone"])
                    email = col2.text_input("Email", value=cust["email"])
                    address = st.text_area("Address", value=cust["address"])
                    status = col1.selectbox("Status", CUSTOMER_STATUS, index=CUSTOMER_STATUS.index(cust["status"]) if cust["status"] in CUSTOMER_STATUS else 0)
                    kyc = col2.selectbox("KYC Status", ["Verified", "Pending"], index=0 if cust["kyc_status"] == "Verified" else 1)
                    if st.form_submit_button("💾 Update Customer", use_container_width=True):
                        self.cust_mgr.update_customer(cust_id, phone=phone, email=email, address=address, status=status, kyc_status=kyc)
                        st.success("Customer updated successfully.")

        with tabs[3]:
            customers = self.db.load("customers")
            del_id = st.selectbox("Select Customer to Delete", customers["customer_id"].tolist(), key="del_sel")
            st.warning("⚠️ This action is irreversible. Please confirm.")
            if st.button("🗑️ Confirm Delete", type="primary"):
                self.cust_mgr.delete_customer(del_id)
                st.success(f"Customer {del_id} deleted.")
                st.rerun()

        with tabs[4]:
            st.dataframe(self.db.load("customers"), use_container_width=True, height=450)
            st.download_button("⬇️ Download All Customers (CSV)", self.db.load("customers").to_csv(index=False),
                                "customers_export.csv", "text/csv")

    # KYC APPROVAL (ADMIN/EMPLOYEE)
    def _page_kyc_approval(self):
        st.subheader("🪪 KYC Verification & Approval")
        st.caption("Only customers who have manually submitted a KYC form and are awaiting review appear in the pending queue below. Not every customer is required to be pending.")

        pending = self.kyc_mgr.pending_queue()
        c1, c2, c3 = st.columns(3)
        customers = self.db.load("customers")
        kyc_all = self.db.load("kyc")
        c1.metric("Pending Review", len(pending))
        c2.metric("Verified Customers", len(customers[customers["kyc_status"] == "Verified"]))
        c3.metric("Total KYC Submissions", len(kyc_all))

        tabs = st.tabs(["🕓 Pending Approvals", "📜 All KYC Records"])

        with tabs[0]:
            if pending.empty:
                st.success("No pending KYC submissions right now.")
            else:
                sel = st.selectbox("Select a Pending Submission (by Customer ID)", pending["customer_id"].tolist())
                if sel:
                    kyc_row = self.kyc_mgr.get_kyc(sel)
                    cust = self.cust_mgr.get_customer(sel)
                    st.markdown('<div class="section-card">', unsafe_allow_html=True)
                    st.markdown(f"#### Reviewing KYC — {cust['name'] if cust else ''} (`{sel}`)")
                    colA, colB = st.columns(2)
                    colA.write(f"**Full Name (as per KYC):** {kyc_row['full_name']}")
                    colB.write(f"**PAN Number:** {kyc_row['pan_number']}")
                    colA.write(f"**Aadhaar Number:** {kyc_row['aadhaar_number']}")
                    colB.write(f"**Occupation:** {kyc_row['occupation']}")
                    colA.write(f"**Annual Income:** {fmt_currency(kyc_row['annual_income'])}")
                    colB.write(f"**Document Type:** {kyc_row['document_type']}")
                    colA.write(f"**Document Number:** {kyc_row['document_number']}")
                    colB.write(f"**Nominee Name:** {kyc_row['nominee_name']}")
                    st.write(f"**Address Proof:** {kyc_row['address_proof']}")
                    st.write(f"**Submitted On:** {kyc_row['submitted_on']}")

                    remarks = st.text_area("Reviewer Remarks", value="KYC verified and approved.")
                    colX, colY = st.columns(2)
                    if colX.button("✅ Approve KYC", use_container_width=True, type="primary"):
                        ok, msg = self.kyc_mgr.approve(sel, st.session_state.user["username"], remarks)
                        st.success(msg) if ok else st.error(msg)
                        st.rerun()
                    if colY.button("❌ Reject KYC", use_container_width=True):
                        ok, msg = self.kyc_mgr.reject(sel, st.session_state.user["username"], remarks or "Documents insufficient / incorrect.")
                        st.warning(msg) if ok else st.error(msg)
                        st.rerun()
                    st.markdown('</div>', unsafe_allow_html=True)

        with tabs[1]:
            st.dataframe(kyc_all, use_container_width=True, height=400)
            if not kyc_all.empty:
                st.download_button("⬇️ Download KYC Records (CSV)", kyc_all.to_csv(index=False),
                                    "kyc_records.csv", "text/csv")

    #  ACCOUNTS
    def _page_account_management(self):
        st.subheader("💳 Account Management")
        tabs = st.tabs(["➕ Open Account", "💰 Deposit / Withdraw", "🔁 Fund Transfer",
                        "📄 Mini Statement", "📊 Account Summary"])

        customers = self.db.load("customers")
        cust_ids = customers["customer_id"].tolist()

        with tabs[0]:
            with st.form("open_acc_form"):
                cust_id = st.selectbox("Customer", cust_ids)
                acc_type = st.selectbox("Account Type", ACCOUNT_TYPES)
                cust = self.cust_mgr.get_customer(cust_id) if cust_id else None
                branch = st.selectbox("Branch", BRANCHES, index=BRANCHES.index(cust["branch"]) if cust else 0)
                initial_deposit = st.number_input("Initial Deposit (₹)", min_value=0.0, step=500.0)
                if st.form_submit_button("✅ Open Account", use_container_width=True):
                    acc_num = self.acc_mgr.open_account(cust_id, acc_type, branch, initial_deposit)
                    st.success(f"Account opened successfully! Account Number: **{acc_num}**")

        with tabs[1]:
            accounts = self.db.load("accounts")
            acc_num = st.selectbox("Select Account", accounts["account_number"].tolist(), key="dw_acc")
            if acc_num:
                acc = self.acc_mgr.get_account(acc_num)
                st.info(f"Current Balance: **{fmt_currency(acc['balance'])}**  |  Type: {acc['account_type']}  |  Branch: {acc['branch']}")
                col1, col2 = st.columns(2)
                with col1:
                    dep_amt = st.number_input("Deposit Amount (₹)", min_value=0.0, step=100.0, key="dep_amt")
                    dep_type = st.selectbox("Deposit Type", ["Deposit", "Cash Deposit", "Cheque Deposit"])
                    if st.button("💰 Deposit", use_container_width=True):
                        ok, msg = self.txn_mgr.deposit(acc_num, dep_amt, dep_type)
                        st.success(f"Deposit successful. Txn ID: {msg}") if ok else st.error(msg)
                with col2:
                    wd_amt = st.number_input("Withdraw Amount (₹)", min_value=0.0, step=100.0, key="wd_amt")
                    wd_type = st.selectbox("Withdrawal Type", ["Withdrawal", "ATM Withdrawal"])
                    if st.button("💸 Withdraw", use_container_width=True):
                        ok, msg = self.txn_mgr.withdraw(acc_num, wd_amt, wd_type)
                        st.success(f"Withdrawal successful. Txn ID: {msg}") if ok else st.error(msg)

        with tabs[2]:
            accounts = self.db.load("accounts")
            col1, col2 = st.columns(2)
            from_acc = col1.selectbox("From Account", accounts["account_number"].tolist(), key="from_acc")
            to_acc = col2.selectbox("To Account", accounts["account_number"].tolist(), key="to_acc")
            transfer_mode = st.selectbox("Transfer Mode", ["UPI", "NEFT", "IMPS", "RTGS"])
            amount = st.number_input("Amount (₹)", min_value=0.0, step=100.0, key="transfer_amt")
            if st.button("🔁 Transfer Funds", use_container_width=True):
                if from_acc == to_acc:
                    st.error("Source and destination accounts must differ.")
                else:
                    ok, msg = self.txn_mgr.transfer(from_acc, to_acc, amount, transfer_mode)
                    st.success(f"Transfer successful via {transfer_mode}. Txn ID: {msg}") if ok else st.error(msg)

        with tabs[3]:
            accounts = self.db.load("accounts")
            acc_num = st.selectbox("Select Account", accounts["account_number"].tolist(), key="mini_acc")
            n = st.slider("Number of recent transactions", 5, 50, 10)
            if acc_num:
                stmt = self.txn_mgr.mini_statement(acc_num, n)
                st.dataframe(stmt, use_container_width=True, height=350)

        with tabs[4]:
            accounts = self.db.load("accounts")
            st.dataframe(accounts, use_container_width=True, height=350)
            col1, col2, col3 = st.columns(3)
            col1.metric("Total Accounts", len(accounts))
            col2.metric("Total Balance", fmt_currency(accounts["balance"].sum() if not accounts.empty else 0))
            col3.metric("Avg Balance", fmt_currency(accounts["balance"].mean() if not accounts.empty else 0))
            fig = px.pie(accounts, names="account_type", title="Accounts by Type", hole=0.4,
                         color_discrete_sequence=ChartEngine.COLORWAY)
            st.plotly_chart(fig, use_container_width=True)

    #  TRANSACTIONS
    def _page_transactions(self):
        st.subheader("💸 Transaction Management")
        st.markdown("#### 🔎 Filter Transaction History")
        col1, col2, col3, col4 = st.columns(4)
        customers = self.db.load("customers")
        cust_filter = col1.selectbox("Customer", ["All"] + customers["customer_id"].tolist())
        branch_filter = col2.selectbox("Branch", ["All"] + BRANCHES)
        month_filter = col3.selectbox("Month", ["All"] + [str(i) for i in range(1, 13)])
        year_filter = col4.selectbox("Year", ["All"] + [str(y) for y in range(2019, datetime.now().year + 1)])

        col5, col6, col7 = st.columns(3)
        min_amt = col5.number_input("Min Amount", min_value=0.0, value=0.0)
        max_amt = col6.number_input("Max Amount", min_value=0.0, value=1000000.0)
        status_filter = col7.selectbox("Status", ["All"] + TXN_STATUS)

        results = self.txn_mgr.get_history(
            customer_id=None if cust_filter == "All" else cust_filter,
            branch=branch_filter, month=month_filter, year=year_filter,
            min_amount=min_amt, max_amount=max_amt, status=status_filter,
        )
        st.write(f"**{len(results)}** transaction(s) found.")
        st.dataframe(results, use_container_width=True, height=400)
        if not results.empty:
            st.download_button("⬇️ Download Filtered Transactions (CSV)", results.to_csv(index=False),
                                "transactions_export.csv", "text/csv")

    # FRAUD DETECTION
    def _page_fraud_detection(self):
        st.subheader("🚨 Fraud Detection & Risk Analysis")
        with st.spinner("Running fraud detection engine across all transactions..."):
            flagged = self.fraud_engine.suspicious_report()

        c1, c2, c3, c4 = st.columns(4)
        all_txns = self.db.load("transactions")
        c1.metric("Total Transactions Scanned", len(all_txns))
        c2.metric("Suspicious Transactions", len(flagged))
        c3.metric("Critical Risk", len(flagged[flagged["risk_level"] == "Critical"]) if not flagged.empty else 0)
        c4.metric("High Risk", len(flagged[flagged["risk_level"] == "High"]) if not flagged.empty else 0)

        st.plotly_chart(ChartEngine.fraud_risk_distribution(all_txns), use_container_width=True)

        st.markdown("#### 🕵️ Suspicious Transaction Report")
        if flagged.empty:
            st.success("No suspicious transactions detected.")
        else:
            st.dataframe(flagged, use_container_width=True, height=400)
            st.download_button("⬇️ Download Suspicious Report (CSV)", flagged.to_csv(index=False),
                                "suspicious_transactions.csv", "text/csv")

    # REPORTS
    def _page_reports(self):
        st.subheader("📑 Reports Center")
        tabs = st.tabs(["Customer Activity Report", "Monthly Transaction Report",
                        "Branch Report", "Employee Report", "Top Customers"])

        with tabs[0]:
            customers = self.db.load("customers")
            cust_id = st.selectbox("Select Customer", customers["customer_id"].tolist(), key="rep_cust")
            if cust_id and st.button("📊 Generate Report", use_container_width=True):
                self._render_customer_activity_report(cust_id)

        with tabs[1]:
            year = st.selectbox("Year", ["All"] + [str(y) for y in range(2019, datetime.now().year + 1)], key="mrep_year")
            report = self.report_engine.monthly_transaction_report(year)
            st.dataframe(report, use_container_width=True)
            if not report.empty:
                fig = px.bar(report, x="month", y="total_amount", title="Monthly Transaction Report",
                             color_discrete_sequence=["#0B3D91"])
                st.plotly_chart(fig, use_container_width=True)

        with tabs[2]:
            branch_summary, txn_counts = self.report_engine.branch_report()
            st.dataframe(branch_summary, use_container_width=True)
            st.plotly_chart(ChartEngine.branch_performance(branch_summary), use_container_width=True)
            st.dataframe(txn_counts, use_container_width=True)

        with tabs[3]:
            employees = self.report_engine.employee_report()
            st.dataframe(employees, use_container_width=True, height=350)
            st.plotly_chart(ChartEngine.employee_performance(employees), use_container_width=True)

        with tabs[4]:
            by = st.radio("Rank By", ["Deposits", "Withdrawals"], horizontal=True)
            top = self.report_engine.top_customers(15, "deposit" if by == "Deposits" else "withdrawal")
            st.dataframe(top, use_container_width=True)
            if not top.empty:
                fig = px.bar(top, x="name", y="total_amount", title=f"Top Customers by {by}",
                             color_discrete_sequence=["#1E88E5"])
                st.plotly_chart(fig, use_container_width=True)

    def _render_customer_activity_report(self, customer_id):
        report = self.report_engine.customer_activity_report(customer_id)
        if not report:
            st.error("No data found for this customer.")
            return
        cust = report["customer"]
        st.markdown('<div class="section-card">', unsafe_allow_html=True)
        st.markdown(f"### 📋 Customer Activity Report — {cust['name']} (`{cust['customer_id']}`)")
        c1, c2, c3 = st.columns(3)
        c1.write(f"**Branch:** {cust['branch']}")
        c2.write(f"**Phone:** {cust['phone']}")
        c3.write(f"**Category:** {cust['customer_category']}")
        c1.markdown(f"**Status:** {status_badge(cust['status'])}", unsafe_allow_html=True)
        c2.write(f"**KYC:** {cust['kyc_status']}")
        c3.write(f"**Customer Since:** {cust['created_on']}")
        st.markdown("---")

        m1, m2, m3, m4 = st.columns(4)
        kpi_card(m1, "Current Balance", fmt_currency(report["total_balance"]), "💰")
        kpi_card(m2, "Highest Deposit", fmt_currency(report["highest_deposit"]), "⬆️")
        kpi_card(m3, "Highest Withdrawal", fmt_currency(report["highest_withdrawal"]), "⬇️")
        kpi_card(m4, "Avg Transaction", fmt_currency(report["average_transaction"]), "📊")

        st.markdown("###")
        m5, m6, m7 = st.columns(3)
        kpi_card(m5, "Total Transactions", report["total_transactions"], "🔄")
        kpi_card(m6, "Risk Score", f"{report['risk_score']}/100", "⚠️")
        kpi_card(m7, "Account Health", report["account_health"], "🏥")

        st.markdown("#### 📈 Monthly Activity")
        if not report["monthly_activity"].empty:
            fig = px.bar(report["monthly_activity"], x="month", y="total_amount",
                         title="Monthly Transaction Activity", color_discrete_sequence=["#0B3D91"])
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No transaction history available.")

        st.markdown("#### 🧾 Recent Transactions")
        st.dataframe(report["transactions"].head(20), use_container_width=True, height=300)

        st.markdown("#### 💡 Final Recommendation")
        st.info(report["recommendation"])
        st.markdown('</div>', unsafe_allow_html=True)

    # BACKUP & LOGS
    def _page_backup_logs(self):
        st.subheader("🗄️ Backup, Restore & Logs")
        col1, col2 = st.columns(2)
        with col1:
            st.markdown('<div class="section-card">', unsafe_allow_html=True)
            st.markdown("#### 💾 Backup & Restore")
            if st.button("📦 Create Full Backup", use_container_width=True):
                dest = self.db.backup_all()
                st.success(f"Backup created at: {dest}")
            if st.button("♻️ Restore Latest Backup", use_container_width=True):
                if self.db.restore_latest():
                    st.success("Restored from the most recent backup.")
                else:
                    st.warning("No backups found.")
            st.markdown('</div>', unsafe_allow_html=True)
        with col2:
            st.markdown('<div class="section-card">', unsafe_allow_html=True)
            st.markdown("#### 📤 Export Data")
            table = st.selectbox("Select Table to Export", list(FILES.keys()))
            df = self.db.load(table)
            st.download_button(f"⬇️ Download {table}.csv", df.to_csv(index=False), f"{table}_export.csv", "text/csv")
            st.markdown('</div>', unsafe_allow_html=True)

        st.markdown("#### 📜 Audit Trail")
        st.dataframe(self.db.load("audit_log").sort_values("timestamp", ascending=False), use_container_width=True, height=300)

        st.markdown("#### 🕓 Activity Log")
        st.dataframe(self.db.load("activity_log").sort_values("timestamp", ascending=False), use_container_width=True, height=300)

    # CUSTOMER SELF-SERVICE
    def _page_my_accounts(self):
        cust_id = st.session_state.user["linked_id"]
        cust = self.cust_mgr.get_customer(cust_id)
        st.subheader(f"💳 My Accounts — {cust['name'] if cust else cust_id}")
        accounts = self.acc_mgr.get_accounts_by_customer(cust_id)
        if accounts.empty:
            st.info("No accounts found for your profile.")
            return
        cols = st.columns(len(accounts)) if len(accounts) <= 4 else st.columns(4)
        for i, (_, acc) in enumerate(accounts.iterrows()):
            kpi_card(cols[i % len(cols)], f"{acc['account_type']} ({acc['account_number']})", fmt_currency(acc["balance"]), "💳")
        st.markdown("###")
        st.dataframe(accounts, use_container_width=True)

    def _page_my_transactions(self):
        cust_id = st.session_state.user["linked_id"]
        st.subheader("💸 My Transactions")
        results = self.txn_mgr.get_history(customer_id=cust_id)
        st.dataframe(results, use_container_width=True, height=400)
        if not results.empty:
            st.download_button("⬇️ Download My Statement (CSV)", results.to_csv(index=False),
                                "my_statement.csv", "text/csv")

    def _page_my_kyc(self):
        cust_id = st.session_state.user["linked_id"]
        cust = self.cust_mgr.get_customer(cust_id)
        st.subheader("🪪 KYC Verification")

        current_status = cust["kyc_status"] if cust else "Pending"
        st.markdown(f"**Current KYC Status:** {status_badge('Active' if current_status == 'Verified' else 'Inactive')}", unsafe_allow_html=True)

        existing = self.kyc_mgr.get_kyc(cust_id)

        if current_status == "Verified" and existing is not None and existing.get("status") == "Approved":
            st.success("✅ Your KYC has been reviewed and approved by the bank. No further action is needed.")
            st.markdown('<div class="section-card">', unsafe_allow_html=True)
            st.markdown("#### Approved KYC Details")
            colA, colB = st.columns(2)
            colA.write(f"**Full Name:** {existing['full_name']}")
            colB.write(f"**PAN Number:** {existing['pan_number']}")
            colA.write(f"**Aadhaar Number:** {existing['aadhaar_number']}")
            colB.write(f"**Document Type:** {existing['document_type']}")
            colA.write(f"**Approved By:** {existing['reviewed_by']}")
            colB.write(f"**Approved On:** {existing['reviewed_on']}")
            st.markdown('</div>', unsafe_allow_html=True)
            return

        if existing is not None and existing.get("status") == "Pending":
            st.info("📨 Your KYC form has been submitted and is awaiting review by bank staff. You'll be notified once it's approved.")
            st.markdown('<div class="section-card">', unsafe_allow_html=True)
            st.markdown("#### Your Submitted Details")
            colA, colB = st.columns(2)
            colA.write(f"**Full Name:** {existing['full_name']}")
            colB.write(f"**PAN Number:** {existing['pan_number']}")
            colA.write(f"**Document Type:** {existing['document_type']}")
            colB.write(f"**Submitted On:** {existing['submitted_on']}")
            st.markdown('</div>', unsafe_allow_html=True)
            return

        if existing is not None and existing.get("status") == "Rejected":
            st.error(f"❌ Your previous KYC submission was rejected. Reason: {existing.get('remarks', '')}. Please resubmit below.")

        st.markdown('<div class="section-card">', unsafe_allow_html=True)
        st.markdown("#### 📝 Fill KYC Details")
        with st.form("kyc_submit_form"):
            col1, col2 = st.columns(2)
            full_name = col1.text_input("Full Name (as per ID proof)", value=cust["name"] if cust else "")
            pan_number = col2.text_input("PAN Number", placeholder="ABCDE1234F")
            aadhaar_number = col1.text_input("Aadhaar Number", placeholder="XXXX-XXXX-XXXX")
            occupation = col2.selectbox("Occupation", ["Salaried", "Self-Employed", "Business Owner",
                                                         "Student", "Homemaker", "Retired", "Other"])
            annual_income = col1.number_input("Annual Income (₹)", min_value=0.0, step=10000.0)
            document_type = col2.selectbox("ID Document Type", ["Aadhaar Card", "Passport", "Voter ID",
                                                                  "Driving License", "PAN Card"])
            document_number = col1.text_input("Document Number")
            nominee_name = col2.text_input("Nominee Name")
            address_proof = st.text_area("Address Proof Details", value=cust["address"] if cust else "")

            submitted = st.form_submit_button("📤 Submit KYC for Approval", use_container_width=True)
            if submitted:
                if not full_name or not pan_number or not aadhaar_number or not document_number:
                    st.error("Please fill in all mandatory fields: Full Name, PAN, Aadhaar, Document Number.")
                else:
                    self.kyc_mgr.submit_kyc(cust_id, full_name, pan_number, aadhaar_number, occupation,
                                             annual_income, document_type, document_number,
                                             address_proof, nominee_name)
                    st.success("Your KYC has been submitted successfully and is now pending admin approval.")
                    st.rerun()
        st.markdown('</div>', unsafe_allow_html=True)

    def _page_my_activity_report(self):
        cust_id = st.session_state.user["linked_id"]
        st.subheader("📋 My Activity Report")
        self._render_customer_activity_report(cust_id)

# ENTRY POINT

def main():
    app = BankingApp()
    app.run()


if __name__ == "__main__":
    main()
