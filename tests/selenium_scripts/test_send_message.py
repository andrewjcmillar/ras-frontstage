import unittest

from selenium import webdriver

from config import SecureMessaging


class SendMessage(unittest.TestCase):
    def setUp(self):
        self.driver = webdriver.Chrome(executable_path=SecureMessaging.chrome_driver)
        self.driver.implicitly_wait(30)

        # navigate to the application home page
        self.driver.get("http://0.0.0.0:5001/secure-message/create-message")

    def send_message_test(self):
        self.subject_field = self.driver.find_element_by_id("secure-message-subject").send_keys('Test Subject')
        self.body_field = self.driver.find_element_by_id("secure-message-body").send_keys('Test Body')
        self.driver.find_element_by_id("send-message").click()

    def tearDown(self):
        # close the browser window
        self.driver.quit()

if __name__ == '__main__':
    unittest.main()
