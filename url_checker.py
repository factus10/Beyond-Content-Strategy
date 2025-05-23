#!/usr/bin/env python3
"""
URL Status Checker with Basic Authentication Support

This script checks a list of URLs and returns their HTTP status codes.
Supports basic authentication and handles various error conditions.
"""

import requests
from requests.auth import HTTPBasicAuth
import csv
import json
from typing import List, Dict, Optional, Tuple
import argparse
import sys
from urllib.parse import urlparse


class URLChecker:
    def __init__(self, timeout: int = 10, verify_ssl: bool = True):
        """
        Initialize the URL checker.
        
        Args:
            timeout: Request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
        """
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        
    def check_url(self, url: str, username: str = None, password: str = None) -> Dict:
        """
        Check a single URL and return status information.
        
        Args:
            url: URL to check
            username: Optional username for basic auth
            password: Optional password for basic auth
            
        Returns:
            Dictionary containing URL, status_code, status_text, and response_time
        """
        result = {
            'url': url,
            'status_code': None,
            'status_text': 'Unknown',
            'response_time': None,
            'error': None
        }
        
        try:
            # Prepare authentication if provided
            auth = HTTPBasicAuth(username, password) if username and password else None
            
            # Make the request
            response = self.session.get(
                url, 
                auth=auth, 
                timeout=self.timeout, 
                verify=self.verify_ssl,
                allow_redirects=True
            )
            
            result['status_code'] = response.status_code
            result['status_text'] = response.reason
            result['response_time'] = response.elapsed.total_seconds()
            
        except requests.exceptions.Timeout:
            result['error'] = 'Timeout'
            result['status_text'] = 'Request timed out'
            
        except requests.exceptions.ConnectionError:
            result['error'] = 'Connection Error'
            result['status_text'] = 'Failed to connect'
            
        except requests.exceptions.SSLError:
            result['error'] = 'SSL Error'
            result['status_text'] = 'SSL certificate error'
            
        except requests.exceptions.InvalidURL:
            result['error'] = 'Invalid URL'
            result['status_text'] = 'URL format is invalid'
            
        except requests.exceptions.RequestException as e:
            result['error'] = 'Request Error'
            result['status_text'] = str(e)
            
        except Exception as e:
            result['error'] = 'Unexpected Error'
            result['status_text'] = str(e)
            
        return result
    
    def check_urls(self, urls: List[str], auth_config: Dict = None) -> List[Dict]:
        """
        Check multiple URLs.
        
        Args:
            urls: List of URLs to check
            auth_config: Dictionary mapping URLs to auth credentials
                        Format: {url: {'username': 'user', 'password': 'pass'}}
            
        Returns:
            List of dictionaries containing results for each URL
        """
        results = []
        auth_config = auth_config or {}
        
        for url in urls:
            print(f"Checking: {url}")
            
            # Get auth credentials for this URL if available
            auth = auth_config.get(url, {})
            username = auth.get('username')
            password = auth.get('password')
            
            result = self.check_url(url, username, password)
            results.append(result)
            
            # Print immediate result
            status = result['status_code'] or 'ERROR'
            print(f"  Status: {status} - {result['status_text']}")
            
        return results


def load_urls_from_file(filename: str) -> List[str]:
    """Load URLs from a text file (one URL per line)."""
    urls = []
    try:
        with open(filename, 'r') as f:
            for line in f:
                url = line.strip()
                if url and not url.startswith('#'):  # Skip empty lines and comments
                    urls.append(url)
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
        sys.exit(1)
    return urls


def load_auth_from_file(filename: str) -> Dict:
    """
    Load authentication configuration from JSON file.
    Expected format:
    {
        "https://example.com": {"username": "user1", "password": "pass1"},
        "https://api.example.com": {"username": "user2", "password": "pass2"}
    }
    """
    try:
        with open(filename, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Warning: Auth file '{filename}' not found. Proceeding without authentication.")
        return {}
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON in auth file '{filename}'.")
        sys.exit(1)


def save_results_csv(results: List[Dict], filename: str):
    """Save results to CSV file."""
    with open(filename, 'w', newline='') as f:
        fieldnames = ['url', 'status_code', 'status_text', 'response_time', 'error']
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)


def save_results_json(results: List[Dict], filename: str):
    """Save results to JSON file."""
    with open(filename, 'w') as f:
        json.dump(results, f, indent=2)


def print_summary(results: List[Dict]):
    """Print a summary of the results."""
    total = len(results)
    success = len([r for r in results if r['status_code'] and 200 <= r['status_code'] < 300])
    redirects = len([r for r in results if r['status_code'] and 300 <= r['status_code'] < 400])
    client_errors = len([r for r in results if r['status_code'] and 400 <= r['status_code'] < 500])
    server_errors = len([r for r in results if r['status_code'] and 500 <= r['status_code'] < 600])
    network_errors = len([r for r in results if r['error']])
    
    print(f"\n{'='*50}")
    print(f"SUMMARY")
    print(f"{'='*50}")
    print(f"Total URLs checked: {total}")
    print(f"Successful (2xx): {success}")
    print(f"Redirects (3xx): {redirects}")
    print(f"Client errors (4xx): {client_errors}")
    print(f"Server errors (5xx): {server_errors}")
    print(f"Network errors: {network_errors}")


def main():
    parser = argparse.ArgumentParser(description='Check URL status codes with optional basic authentication')
    parser.add_argument('urls', nargs='*', help='URLs to check (or use --file)')
    parser.add_argument('--file', '-f', help='File containing URLs (one per line)')
    parser.add_argument('--auth-file', help='JSON file containing authentication credentials')
    parser.add_argument('--username', '-u', help='Username for basic auth (applies to all URLs)')
    parser.add_argument('--password', '-p', help='Password for basic auth (applies to all URLs)')
    parser.add_argument('--timeout', '-t', type=int, default=10, help='Request timeout in seconds (default: 10)')
    parser.add_argument('--no-ssl-verify', action='store_true', help='Disable SSL certificate verification')
    parser.add_argument('--output-csv', help='Save results to CSV file')
    parser.add_argument('--output-json', help='Save results to JSON file')
    parser.add_argument('--quiet', '-q', action='store_true', help='Suppress progress output')
    
    args = parser.parse_args()
    
    # Get URLs from command line or file
    if args.file:
        urls = load_urls_from_file(args.file)
    elif args.urls:
        urls = args.urls
    else:
        print("Error: Please provide URLs either as arguments or via --file option")
        sys.exit(1)
    
    if not urls:
        print("Error: No URLs to check")
        sys.exit(1)
    
    # Load authentication configuration
    auth_config = {}
    if args.auth_file:
        auth_config = load_auth_from_file(args.auth_file)
    elif args.username and args.password:
        # Apply same credentials to all URLs
        auth_config = {url: {'username': args.username, 'password': args.password} for url in urls}
    
    # Create checker and check URLs
    checker = URLChecker(timeout=args.timeout, verify_ssl=not args.no_ssl_verify)
    
    if not args.quiet:
        print(f"Checking {len(urls)} URLs...")
        print("-" * 50)
    
    results = checker.check_urls(urls, auth_config)
    
    # Save results if requested
    if args.output_csv:
        save_results_csv(results, args.output_csv)
        print(f"\nResults saved to: {args.output_csv}")
    
    if args.output_json:
        save_results_json(results, args.output_json)
        print(f"\nResults saved to: {args.output_json}")
    
    # Print summary
    if not args.quiet:
        print_summary(results)


if __name__ == "__main__":
    main()


# Example usage:
"""
# Check URLs from command line
python url_checker.py https://google.com https://httpbin.org/status/404

# Check URLs from file
python url_checker.py --file urls.txt

# Check URLs with basic auth (same credentials for all)
python url_checker.py --file urls.txt --username myuser --password mypass

# Check URLs with different auth per URL (using auth config file)
python url_checker.py --file urls.txt --auth-file auth.json

# Save results to CSV
python url_checker.py --file urls.txt --output-csv results.csv

# Example auth.json file:
{
    "https://api.example.com": {
        "username": "api_user",
        "password": "api_password"
    },
    "https://secure.example.com": {
        "username": "secure_user", 
        "password": "secure_password"
    }
}

# Example urls.txt file:
https://google.com
https://httpbin.org/status/200
https://httpbin.org/status/404
https://httpbin.org/status/500
"""
