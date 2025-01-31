import os

class Config:
    LOGO_URL = os.getenv('LOGO_URL', '../static/riauth.svg')
    BG_URL = os.getenv('BG_URL', 'https://cdn.discordapp.com/attachments/706221390289961101/1057304820572233818/logo.png')
    DEFAULT_COLOR = os.getenv('DEFAULT_COLOR', '000000')
