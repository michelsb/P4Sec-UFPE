#!/usr/bin/env python
import os
from api.api import app

if __name__ == '__main__':
    # Starting the application
    app.debug = True
    host = os.environ.get('IP', '0.0.0.0')
    port = int(os.environ.get('PORT', 5000))
    app.run(host=host, port=port)