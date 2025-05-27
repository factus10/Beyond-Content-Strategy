import requests
from bs4 import BeautifulSoup
import sys
import csv
from urllib.parse import urljoin
import base64
import getpass

def find_matching_links(urls, pattern, output_file, username=None, password=None):
    """
    Find links containing a specific pattern in a list of URLs and write to CSV.
    Supports basic authentication.
    
    Args:
        urls (list): List of URLs to search
        pattern (str): Pattern to look for in links
        output_file (str): Path to output CSV file
        username (str, optional): Username for basic authentication
        password (str, optional): Password for basic authentication
    
    Returns:
        int: Total number of matching links found
    """
    total_matches = 0
    
    # Prepare authentication if provided
    auth = None
    headers = {}
    if username and password:
        auth = (username, password)
        # Alternative method using Authorization header
        # auth_string = f"{username}:{password}"
        # encoded_auth = base64.b64encode(auth_string.encode()).decode()
        # headers = {"Authorization": f"Basic {encoded_auth}"}
    
    # Create and write headers to CSV file
    with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
        csv_writer = csv.writer(csvfile)
        csv_writer.writerow(['Source URL', 'Matching Link URL', 'Link Text'])
        
        for url in urls:
            try:
                print(f"Processing: {url}")
                
                # Make the request with authentication
                response = requests.get(
                    url, 
                    auth=auth,
                    headers=headers,
                    timeout=30
                )
                
                # Check if request was successful
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    matches_found = 0
                    
                    # Find all anchor tags
                    for a_tag in soup.find_all('a', href=True):
                        href = a_tag['href']
                        
                        # Create absolute URL if relative
                        full_url = urljoin(url, href)
                        
                        # Check if the pattern exists in the URL
                        if pattern in full_url:
                            link_text = a_tag.get_text(strip=True) or '[No text]'
                            
                            # Write to CSV
                            csv_writer.writerow([url, full_url, link_text])
                            matches_found += 1
                            total_matches += 1
                    
                    print(f"  Found {matches_found} matching links in {url}")
                else:
                    print(f"  Failed to retrieve {url}: Status code {response.status_code}")
                    # Write error to CSV
                    csv_writer.writerow([url, f"ERROR: Status code {response.status_code}", ""])
                    
            except Exception as e:
                print(f"  Error processing {url}: {str(e)}")
                # Write error to CSV
                csv_writer.writerow([url, f"ERROR: {str(e)}", ""])
    
    return total_matches

def main():
    if len(sys.argv) < 4:
        print("Usage: python link_finder.py <pattern> <url_file> <output_csv> [username]")
        print("Example: python link_finder.py link.aspx urls.txt results.csv")
        print("If username is provided, you will be prompted for password")
        sys.exit(1)
    
    pattern = sys.argv[1]
    url_file = sys.argv[2]
    output_file = sys.argv[3]
    
    # Check if authentication is needed
    username = None
    password = None
    if len(sys.argv) >= 5:
        username = sys.argv[4]
        password = getpass.getpass("Enter password for basic authentication: ")
    
    try:
        with open(url_file, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"Error reading URL file: {str(e)}")
        sys.exit(1)
    
    print(f"Searching for links containing '{pattern}' in {len(urls)} URLs")
    if username:
        print(f"Using basic authentication with username: {username}")
    print(f"Results will be saved to {output_file}")
    
    total_matches = find_matching_links(urls, pattern, output_file, username, password)
    
    print(f"\nCompleted! Total matching links found: {total_matches}")
    print(f"Results saved to {output_file}")

if __name__ == "__main__":
    main()
