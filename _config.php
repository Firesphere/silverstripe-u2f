<?php

use SilverStripe\Control\Director;

// U2F only works on SSL connections
Director::forceSSL();