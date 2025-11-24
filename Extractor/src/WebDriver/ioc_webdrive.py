import traceback

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager

from ..Logger.ioc_logger import *

class IOCWebNev:
    def create_webdriver():
        try:
            chrome_service = Service(ChromeDriverManager().install())
            chrome_options = Options()
            options = [
                "--headless",
                "--disable-gpu",
                "--window-size=1920,1200",
                "--ignore-certificate-errors",
                "--disable-extensions",
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-blink-features=AutomationControlled",
                "--disable-notifications",
                "--disable-popup-blocking"
            ]
            
            for option in options:
                chrome_options.add_argument(option)
            
            chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
            chrome_options.add_experimental_option('useAutomationExtension', False)
            
            driver = webdriver.Chrome(service=chrome_service, options=chrome_options)
            IOCLogger.log_message("WebDriver Created Successfully")
            return driver
        except Exception as e:
            IOCLogger.log_message(f"Error Creating WebDriver: {e}")
            traceback.print_exc()
            return None