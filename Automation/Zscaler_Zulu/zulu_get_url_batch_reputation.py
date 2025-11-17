"""
Zscaler Zulu Batch URL Reputation Check

CORE FUNCTION: zulu_get_url_batch_reputation(urls)

PURPOSE:
Analyze multiple URLs in batch with comprehensive results from Zscaler Zulu free service

INPUT ATTRIBUTES:
- urls (List[str], REQUIRED): List of URLs to analyze in batch
  * Format: Each URL must include protocol (http:// or https://)
  * Example: ["https://site1.com", "https://site2.com", "https://site3.com"]
  * Validation: Must be non-empty list, max 20 URLs recommended
  * Constraints: Rate limiting applied (3-second delay between requests)

OUTPUT ATTRIBUTES:
Success Response:
- success (bool): Batch operation success status (True)
- total_urls (int): Total number of URLs provided
- processed_urls (int): Number of successfully processed URLs
- safe_count (int): Number of safe URLs
- malicious_count (int): Number of malicious URLs
- unknown_count (int): Number of unknown/pending URLs
- batch_processing (bool): Indicates batch mode (True)
- service (str): Service identifier ("zscaler_zulu")
- zero_dependencies (bool): Indicates zero external dependencies (True)
- processing_time_seconds (float): Total batch processing time
- timestamp (float): Unix timestamp
- results (List[Dict]): Individual URL results with full details
- safe_urls (List[str]): List of URLs marked as safe
- malicious_urls (List[str]): List of URLs marked as malicious
- unknown_urls (List[str]): List of URLs with unknown/pending status

Individual Result Format (in results array):
- input (str): URL that was checked
- status (str): "safe", "malicious", "unknown", "pending"
- classification (str): Detailed classification
- threat_level (str): "low", "medium", "high", "unknown"
- message (str): Additional details
- service (str): "zscaler_zulu"
- success (bool): Individual check success status

Error Response:
- success (bool): False
- error (bool): True
- message (str): Human-readable error message
- error_type (str): Error type classification
- total_urls (int): Number of URLs provided (if applicable)
- service (str): Service identifier ("zscaler_zulu")
- zero_dependencies (bool): True
- processing_time_seconds (float): Processing time before error
- timestamp (float): Unix timestamp

USAGE:
    urls = ["https://google.com", "https://github.com", "https://suspicious.com"]
    result = zulu_get_url_batch_reputation(urls)
    if result['success']:
        print(f"Safe: {result['safe_count']}, Malicious: {result['malicious_count']}")
        for url_result in result['results']:
            print(f"{url_result['input']}: {url_result['status']}")
    else:
        print(f"Error: {result['message']}")
"""

import time
import urllib.request
import urllib.parse
import urllib.error
from http.cookiejar import CookieJar
from html.parser import HTMLParser
from enum import Enum
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("zscaler_zulu")

# Exceptions
class ZuluError(Exception):
    """Base exception for Zscaler Zulu operations"""
    pass

class ZuluServiceError(ZuluError):
    """Exception for Zscaler Zulu service errors"""
    pass

class ZuluConnectionError(ZuluError):
    """Exception for Zscaler Zulu connection errors"""
    pass

# HTML Parser
class ZuluHTMLParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.csrf_token = None
        self.reputation_status = None
        self.reputation_result = None
        self.report_id = None
        self.queue_hash = None
        self.in_status_element = False
        self.in_result_element = False

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        if tag == 'input' and attrs_dict.get('name') == 'csrf_token':
            self.csrf_token = attrs_dict.get('value')
        if tag == 'span' and attrs_dict.get('id') == 'rep-status':
            self.in_status_element = True
        if tag in ['span', 'div', 'td'] and 'class' in attrs_dict:
            class_value = attrs_dict['class']
            if 'report-icon okay' in class_value:
                self.reputation_result = 'safe'
            elif 'report-icon danger' in class_value:
                self.reputation_result = 'malicious'
        if tag == 'div' and attrs_dict.get('id') == 'parent_id':
            self.in_result_element = True
        if tag == 'div' and attrs_dict.get('id') == 'hash':
            self.in_result_element = True

    def handle_data(self, data):
        if self.in_status_element:
            self.reputation_status = data.strip().lower()
            self.in_status_element = False
        if self.in_result_element:
            if self.report_id is None:
                self.report_id = data.strip()
            elif self.queue_hash is None:
                self.queue_hash = data.strip()
            self.in_result_element = False

# Request Utils
class ZuluRequestor:
    def __init__(self, timeout=120):
        self.base_url = 'https://zulu.zscaler.com/'
        self.timeout = timeout
        self.headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
            'Referer': 'https://zulu.zscaler.com/',
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:91.0) Gecko/20100101 Firefox/91.0',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
        self.cookie_jar = CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.cookie_jar))

    def make_request(self, url, data=None, headers=None):
        try:
            request_headers = self.headers.copy()
            if headers:
                request_headers.update(headers)
            if data:
                encoded_data = urllib.parse.urlencode(data).encode('utf-8')
                request_headers['Content-Type'] = 'application/x-www-form-urlencoded'
                request_headers['Content-Length'] = str(len(encoded_data))
                request = urllib.request.Request(url, data=encoded_data, headers=request_headers)
                request.get_method = lambda: 'POST'
            else:
                request = urllib.request.Request(url, headers=request_headers)
            response = self.opener.open(request, timeout=self.timeout)
            content = response.read()
            if response.info().get('Content-Encoding') == 'gzip':
                import gzip
                content = gzip.decompress(content)
            return content.decode('utf-8', errors='ignore')
        except urllib.error.HTTPError as e:
            raise ZuluServiceError(f"HTTP {e.code}: {e.reason}")
        except urllib.error.URLError as e:
            raise ZuluServiceError(f"Network error: {e.reason}")
        except Exception as e:
            raise ZuluError(f"Request failed: {e}")

# Parse Utils
class ReputationStatus(Enum):
    COMPLETED = 'completed'
    QUEUED = 'queued'
    READY_TO_FETCH = 'ready_to_fetch'
    FAILED = 'failed'
    TIMEOUT = 'timeout'

def extract_csrf_token(html_content):
    parser = ZuluHTMLParser()
    parser.feed(html_content)
    if not parser.csrf_token:
        raise Exception("CSRF token not found in response")
    return parser.csrf_token

def parse_reputation_response(html_content):
    parser = ZuluHTMLParser()
    parser.feed(html_content)
    if parser.reputation_result:
        return ReputationStatus.COMPLETED, parser.reputation_result
    elif parser.reputation_status == 'completed':
        return ReputationStatus.COMPLETED, parser.reputation_result or 'unknown'
    elif parser.reputation_status == 'queued':
        return ReputationStatus.READY_TO_FETCH, parser.report_id
    else:
        return ReputationStatus.TIMEOUT, 'timeout'

def format_reputation_result(input_data, classification, message=''):
    if classification in ['safe', 'okay', 'clean']:
        status = 'safe'
        threat_level = 'low'
    elif classification in ['malicious', 'danger', 'threat']:
        status = 'malicious'
        threat_level = 'high'
    elif classification in ['queued', 'pending']:
        status = 'pending'
        threat_level = 'unknown'
    elif classification in ['timeout', 'failed', 'error']:
        status = 'unknown'
        threat_level = 'unknown'
    else:
        status = 'unknown'
        threat_level = 'unknown'
    return {
        'input': input_data,
        'status': status,
        'classification': classification,
        'threat_level': threat_level,
        'message': message,
        'service': 'zscaler_zulu',
        'timestamp': time.time(),
        'success': status in ['safe', 'malicious'],
        'zulu_free_service': True,
        'zero_dependencies': True
    }

def zulu_get_url_reputation(url):
    start_time = time.time()
    try:
        if not url:
            return {
                'success': False,
                'error': True,
                'message': 'No URL provided',
                'service': 'zscaler_zulu',
                'zero_dependencies': True,
                'timestamp': time.time()
            }
        requestor = ZuluRequestor()
        logger.info(f"Getting URL reputation for: {url}")
        # Get CSRF token
        html = requestor.make_request(requestor.base_url)
        csrf_token = extract_csrf_token(html)
        # Submit URL for analysis
        data = {'csrf_token': csrf_token, 'url': url}
        time.sleep(2)
        response = requestor.make_request(requestor.base_url, data=data)
        status, result_data = parse_reputation_response(response)
        if status == ReputationStatus.COMPLETED:
            result = format_reputation_result(url, result_data)
        else:
            result = format_reputation_result(url, 'unknown', 'Analysis not completed')
        result['processing_time_seconds'] = round(time.time() - start_time, 2)
        return result
    except Exception as e:
        logger.error(f"URL reputation check failed: {e}")
        return {
            'success': False,
            'error': True,
            'message': f'URL reputation error: {str(e)}',
            'error_type': type(e).__name__,
            'input': url,
            'service': 'zscaler_zulu',
            'zero_dependencies': True,
            'processing_time_seconds': round(time.time() - start_time, 2),
            'timestamp': time.time()
        }

def zulu_get_url_batch_reputation(urls):
    start_time = time.time()
    try:
        if not urls:
            return {
                'success': False,
                'error': True,
                'message': 'No URLs provided',
                'service': 'zscaler_zulu',
                'zero_dependencies': True,
                'timestamp': time.time()
            }
        if len(urls) > 20:
            return {
                'success': False,
                'error': True,
                'message': 'Too many URLs (max 20 recommended for batch processing)',
                'total_urls': len(urls),
                'service': 'zscaler_zulu',
                'zero_dependencies': True,
                'timestamp': time.time()
            }
        logger.info(f"Starting batch analysis for {len(urls)} URLs")
        results = []
        safe_urls = []
        malicious_urls = []
        unknown_urls = []
        for url in urls:
            try:
                result = zulu_get_url_reputation(url)
                results.append(result)
                if result['status'] == 'safe':
                    safe_urls.append(url)
                elif result['status'] == 'malicious':
                    malicious_urls.append(url)
                else:
                    unknown_urls.append(url)
                time.sleep(3)
            except Exception as e:
                error_result = {
                    'input': url,
                    'status': 'error',
                    'classification': 'error',
                    'threat_level': 'unknown',
                    'message': str(e),
                    'service': 'zscaler_zulu',
                    'success': False
                }
                results.append(error_result)
                unknown_urls.append(url)
        processing_time = time.time() - start_time
        return {
            'success': True,
            'total_urls': len(urls),
            'processed_urls': len(results),
            'safe_count': len(safe_urls),
            'malicious_count': len(malicious_urls),
            'unknown_count': len(unknown_urls),
            'batch_processing': True,
            'service': 'zscaler_zulu',
            'zero_dependencies': True,
            'processing_time_seconds': round(processing_time, 2),
            'timestamp': time.time(),
            'results': results,
            'safe_urls': safe_urls,
            'malicious_urls': malicious_urls,
            'unknown_urls': unknown_urls
        }
    except Exception as e:
        logger.error(f"Batch URL analysis failed: {e}")
        return {
            'success': False,
            'error': True,
            'message': f'Batch analysis error: {str(e)}',
            'error_type': type(e).__name__,
            'total_urls': len(urls) if urls else 0,
            'service': 'zscaler_zulu',
            'zero_dependencies': True,
            'processing_time_seconds': round(time.time() - start_time, 2),
            'timestamp': time.time()
        }

def main(urls: list):
    result = zulu_get_url_batch_reputation(urls)
    print(f"Batch URL reputation result:")
    print(f"  Total: {result.get('total_urls', 0)}")
    print(f"  Safe: {result.get('safe_count', 0)}")
    print(f"  Malicious: {result.get('malicious_count', 0)}")
    print(f"  Unknown: {result.get('unknown_count', 0)}")
    return result

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        urls = sys.argv[1:]
    else:
        urls = ["https://google.com", "https://github.com", "https://stackoverflow.com"]
    main(urls)
