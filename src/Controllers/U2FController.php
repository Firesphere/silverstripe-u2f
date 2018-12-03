<?php

namespace Firesphere\U2FAuth\Controllers;

use Firesphere\U2FAuth\Providers\U2FProvider;
use SilverStripe\Control\Controller;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Core\Injector\Injector;

/**
 * Class U2FController to handle the communication between the frontend and the verification/registration of keys
 *
 * @package Firesphere\U2FAuth\Controllers
 */
class U2FController extends Controller
{
    /**
     * @var U2FProvider
     */
    protected $provider;

    private static $allowed_actions = [
        'getSignRequest',
        'getAuthRequest',
        'handleRegistration',
        'getAuthenticateRequest',
    ];

    private static $url_handlers = [
        'getdata'             => 'getAuthRequest',
        'register'            => 'handleRegistration',
        'authenticaterequest' => 'getAuthenticateRequest',
    ];

    public function __construct()
    {
        parent::__construct();
        $this->provider = Injector::inst()->get(U2FProvider::class);
    }

    public function getAuthRequest()
    {
        $memberKeys = $this->provider->getKeys();
        if (count($memberKeys)) {
            return $this->getAuthenticateRequest();
        }

        return $this->getSignRequest();
    }

    /**
     * @return false|string
     */
    public function getSignRequest()
    {
        $signRequest = $this->provider->getSignRequest();
        $response = $this->getResponse();

        $response->setBody(json_encode($signRequest));
        $response->addHeader('Content-Type', 'application/json');

        return $response;
    }

    public function getAuthenticateRequest()
    {
        // FIDO gets the tokens from the database
        $request = $this->provider->getAuthResponse('');
        $response = $this->getResponse();

        $response->setBody(json_encode($request));
        $response->addHeader('Content-Type', 'application/json');

        return $response;
    }

    /**
     * @param HTTPRequest $request
     * @return \SilverStripe\Control\HTTPResponse
     * @throws \SilverStripe\ORM\ValidationException
     */
    public function handleRegistration(HTTPRequest $request)
    {
        $data = json_decode($request->postVar('registration'), true);
        $registerRequest = $this->request->getSession()->get('RegisterRequest');

        $response = $this->getResponse();
        $response->setStatusCode(201);
        $response->setBody($this->provider->registerToken($data, $registerRequest));
        $response->addHeader('Content-Type', 'application/json');

        return $response;
    }
}