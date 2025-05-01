import os
import jwt
import time
import hmac
import hashlib
import requests
from flask import Flask, request, jsonify
from github import Github, GithubIntegration

app = Flask(__name__)

# Load secrets from environment variables
APP_ID = os.getenv("APP_ID")
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro:generateContent"

# Validate environment variables
if not all([APP_ID, WEBHOOK_SECRET, GEMINI_API_KEY]):
    raise ValueError("Missing required environment variables: APP_ID, WEBHOOK_SECRET, or GEMINI_API_KEY")

# Load the private key from a file
PRIVATE_KEY_PATH = os.getenv("PRIVATE_KEY_PATH", "private-key.pem")  # Default to 'private-key.pem'
try:
    with open(PRIVATE_KEY_PATH, "r") as key_file:
        private_key = key_file.read()
    if not private_key.strip():
        raise ValueError("Private key file is empty")
except FileNotFoundError:
    raise FileNotFoundError(f"Private key file not found at {PRIVATE_KEY_PATH}. Please ensure it exists.")
except Exception as e:
    raise Exception(f"Error loading private key: {str(e)}")

# Generate a JWT for GitHub App authentication
def generate_jwt():
    now = int(time.time())
    payload = {
        "iat": now,  # Issued at time
        "exp": now + 600,  # Expires in 10 minutes
        "iss": APP_ID  # Issuer (App ID)
    }
    return jwt.encode(payload, private_key, algorithm="RS256")

# Webhook endpoint to handle GitHub events
@app.route("/webhook", methods=["POST"])
def webhook():
    # Verify webhook signature
    signature = request.headers.get("X-Hub-Signature-256", "")
    if not signature:
        return jsonify({"error": "Missing signature"}), 401

    expected_signature = "sha256=" + hmac.new(
        WEBHOOK_SECRET.encode("utf-8"),
        request.data,
        hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(signature, expected_signature):
        return jsonify({"error": "Invalid signature"}), 403

    # Get the event type and payload
    event = request.headers.get("X-GitHub-Event")
    payload = request.get_json()

    if event == "pull_request":
        action = payload["action"]
        if action in ["opened", "synchronize"]:
            pr_number = payload["number"]
            repo_name = payload["repository"]["full_name"]
            print(f"Processing PR #{pr_number} in {repo_name}")

            # Authenticate as the GitHub App
            jwt_token = generate_jwt()
            integration = GithubIntegration(APP_ID, private_key)
            installation_id = payload["installation"]["id"]
            access_token = integration.get_access_token(installation_id).token
            g = Github(access_token)

            # Get PR details
            repo = g.get_repo(repo_name)
            pr = repo.get_pull(pr_number)

            # Review each file in the PR
            for file in pr.get_files():
                if not file.patch:
                    print(f"No patch for {file.filename}, skipping...")
                    continue

                if not file.filename.endswith(('.py', '.js', '.java', '.cpp', '.txt')):
                    print(f"Skipping non-code file: {file.filename}")
                    continue

                print(f"Processing file: {file.filename}")
                prompt = f"""
                Analyze the following diff and provide specific, actionable suggestions for improvement. Focus on:
                - Syntax errors: Identify and suggest fixes (if applicable).
                - Bugs: Point out logical errors or potential issues.
                - Content quality: Suggest improvements for clarity or structure (e.g., for text files).
                - Security: Highlight any security vulnerabilities (if applicable).
                - Best practices: Ensure adherence to best practices (e.g., PEP 8 for Python, ES6 for JavaScript, or clear documentation for text files).
                Provide examples where applicable:
                ```diff
                {file.patch}
                """

                # Call Gemini API
                headers = {"Content-Type": "application/json"}
                data = {
                    "contents": [{"parts": [{"text": prompt}]}],
                    "generationConfig": {"maxOutputTokens": 500}
                }
                try:
                    response = requests.post(
                        f"{GEMINI_ENDPOINT}?key={GEMINI_API_KEY}",
                        headers=headers,
                        json=data
                    )
                    response.raise_for_status()
                    response_data = response.json()
                    if "candidates" in response_data and response_data["candidates"]:
                        review = response_data["candidates"][0]["content"]["parts"][0]["text"]
                    else:
                        review = "Error: No review suggestions provided by Gemini API (empty response)."
                except requests.exceptions.RequestException as e:
                    review = f"Error: Failed to get review from Gemini API ({str(e)})."
                except (KeyError, IndexError) as e:
                    review = f"Error: Invalid response format from Gemini API ({str(e)})."

                # Post comment on PR
                try:
                    pr.create_issue_comment(f"### Review for {file.filename}\n{review}")
                except Exception as e:
                    print(f"Failed to post comment for {file.filename}: {str(e)}")

    return jsonify({"status": "success"}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)