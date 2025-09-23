import time
import os
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import TimeoutException
import hashlib
import json

class WebsiteDownloader:
    def __init__(self, username, password, download_dir):
        self.username = username
        self.password = password
        self.download_dir = os.path.abspath(download_dir)
        self.base_url = "https://virus.exchange/"
        self.downloaded_samples = set()
        self.downloaded_samples_file = "downloaded_samples.json"
        
        os.makedirs(self.download_dir, exist_ok=True)
        self.load_downloaded_samples()
        
        chrome_options = Options()
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_experimental_option("prefs", {
            "download.default_directory": self.download_dir,
            "download.prompt_for_download": False,
            "download.directory_upgrade": True,
            "safebrowsing.enabled": True
        })
        
        self.driver = None
        self.wait = None
        self.chrome_options = chrome_options
    
    def load_downloaded_samples(self):
        try:
            if os.path.exists(self.downloaded_samples_file):
                with open(self.downloaded_samples_file, 'r') as f:
                    self.downloaded_samples = set(json.load(f))
                print(f"loaded {len(self.downloaded_samples)} previously downloaded samples")
        except Exception as e:
            print(f"error loading downloaded samples: {e}")
            self.downloaded_samples = set()
    
    def save_downloaded_samples(self):
        try:
            with open(self.downloaded_samples_file, 'w') as f:
                json.dump(list(self.downloaded_samples), f)
        except Exception as e:
            print(f"error saving downloaded samples: {e}")
    
    def start_browser(self):
        try:
            self.driver = webdriver.Chrome(options=self.chrome_options)
            self.wait = WebDriverWait(self.driver, 20)
            print("Browser started successfully!")
        except Exception as e:
            print(f"error starting browser: {e}")
            raise
    
    def login(self):
        try:
            print("step 1: accessing website")
            self.driver.get(self.base_url)
            
            print("step 2: clicking login link")
            self.wait.until(EC.element_to_be_clickable((By.CSS_SELECTOR, 'a[href="/users/log_in"]'))).click()
            
            print("step 3: waiting for redirect to login page")
            self.wait.until(EC.url_contains("/users/log_in"))
            
            print("step 4: entering credentials")
            username_field = self.wait.until(EC.presence_of_element_located((By.ID, "login_form_email")))
            username_field.clear()
            username_field.send_keys(self.username)
            
            password_field = self.driver.find_element(By.ID, "login_form_password")
            password_field.clear()
            password_field.send_keys(self.password)
            
            print("step 5: cicking sign in button")
            self.driver.find_element(By.CSS_SELECTOR, 'button[phx-disable-with="Signing in..."]').click()
            
            print("step 6: waiting for redirect to target page")
            self.wait.until(EC.url_contains("/samples"))
            print("Login successful!")
            
        except TimeoutException:
            print("Timeout during login process!")
            raise
        except Exception as e:
            print(f"error during login: {e}")
            raise
    
    def get_download_links(self):
        try:
            download_links = self.driver.find_elements(By.XPATH, "//a[contains(text(), 'Download')]")
            
            links_info = []
            for link in download_links:
                href = link.get_attribute('href')
                if href:
                    link_text = link.text.strip()
                    link_id = hashlib.md5((href + link_text).encode()).hexdigest()
                    links_info.append({
                        'element': link,
                        'href': href,
                        'text': link_text,
                        'id': link_id
                    })
            return links_info
        except Exception as e:
            print(f"error getting download links: {e}")
            return []
    
    def download_file(self, link_info):
        try:
            if link_info['id'] in self.downloaded_samples:
                print(f"already downloaded: {link_info['text']}")
                return False
            
            print(f"downloading: {link_info['text']} ({link_info['href']})")
            
            initial_files = set(os.listdir(self.download_dir))
            link_info['element'].click()
            
            download_started = False
            for _ in range(30):
                time.sleep(1)
                current_files = set(os.listdir(self.download_dir))
                if current_files - initial_files:
                    download_started = True
                    break
            
            if not download_started:
                print(f"download failed to start: {link_info['text']}")
                return False
            
            for _ in range(300):
                time.sleep(1)
                if not [f for f in os.listdir(self.download_dir) if f.endswith('.crdownload')]:
                    break
            
            self.downloaded_samples.add(link_info['id'])
            self.save_downloaded_samples()
            print(f"download completed: {link_info['text']}")
            return True
                
        except Exception as e:
            print(f"error downloading file {link_info['text']}: {e}")
            return False
    
    def download_all_current_samples(self):
        print("scanning for download links")
        download_links = self.get_download_links()
        
        if not download_links:
            print("no download links found on the page")
            return 0
        
        print(f"found {len(download_links)} download links")
        downloaded_count = 0
        
        for link_info in download_links:
            if self.download_file(link_info):
                downloaded_count += 1
            time.sleep(2)
        
        return downloaded_count
    
    def monitor_and_download(self, check_interval=60):
        print(f"monitoring: checking every {check_interval} seconds")
        
        while True:
            try:
                print("refreshing page to check for new samples")
                self.driver.refresh()
                time.sleep(5)
                
                downloaded_count = self.download_all_current_samples()
                
                if downloaded_count > 0:
                    print(f"downloaded {downloaded_count} new samples")
                else:
                    print("no new samples to download")
                
                print(f"waiting {check_interval} seconds before next check")
                time.sleep(check_interval)
                
            except KeyboardInterrupt:
                print("Monitoring stopped by user!")
                break
            except Exception as e:
                print(f"error during monitoring: {e}")
                print("retrying in 30 seconds")
                time.sleep(30)
    
    def run(self, continuous=True, check_interval=60):
        try:
            self.start_browser()
            self.login()
            
            print("Downloading all current samples!")
            initial_count = self.download_all_current_samples()
            print(f"Initial download completed. Downloaded {initial_count} samples!")
            
            if continuous:
                self.monitor_and_download(check_interval)
            else:
                print("single run completed")
                
        except Exception as e:
            print(f"error in main execution: {e}")
        finally:
            self.cleanup()
    
    def cleanup(self):
        if self.driver:
            print("Closing browser!")
            self.driver.quit()

def main():
    USERNAME = "your_username_here"
    PASSWORD = "your_password_here"
    DOWNLOAD_DIR = r"your_path_here"
    CHECK_INTERVAL = 15
    
    if USERNAME == "your_username_here" or PASSWORD == "your_password_here":
        print("Please update the USERNAME and PASSWORD in the script before running!")
        return
    
    downloader = WebsiteDownloader(USERNAME, PASSWORD, DOWNLOAD_DIR)
    
    try:
        downloader.run(continuous=True, check_interval=CHECK_INTERVAL)
    except KeyboardInterrupt:
        print("Program interrupted by user!")
    except Exception as e:
        print(f"program error: {e}")

if __name__ == "__main__":
    main()