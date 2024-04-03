from souperscraper import SouperScraper
scraper = SouperScraper(executable_path='./chromedriver')

# Goto Zillow and search for Green Lake, Seattle, WA
scraper.goto('https://www.zillow.com/')
search_bar = scraper.find_element_by_css_selector('input[type="text"]')
search_bar.send_keys('Green Lake, Seattle, WA')
search_bar.submit()

# Click the 'For rent' button when asked
for_rent_button = scraper.find_element_by_text('For rent')
for_rent_button.click()

# Handle bot check
if scraper.find_elements_by_id('px-captcha'):
    input('Handle the bot check manually or script it here. Press enter to continue...')

# Wait for results to load
# Do stuff with results    