<?php

namespace Firesphere\U2FAuth\Providers;

use Firesphere\BootstrapMFA\Interfaces\MFAProvider;
use Firesphere\BootstrapMFA\Providers\BootstrapMFAProvider;
use Firesphere\U2FAuth\Models\FidoKey;
use SilverStripe\Control\Controller;
use SilverStripe\Control\Director;
use SilverStripe\ORM\DataList;
use U2F\RegistrationRequest;
use U2F\RegistrationResponse;
use U2F\SignatureRequest;
use U2F\SignatureResponse;

class U2FProvider extends BootstrapMFAProvider implements MFAProvider
{

    /**
     * Generate a signing request to register new keys
     *
     * @return array
     */
    public function getSignRequest()
    {
        $keys = $this->getKeys();

        $registrationRequest = new RegistrationRequest(Director::absoluteBaseURL(), $keys);

        Controller::curr()->getRequest()->getSession()->set('RegisterRequest', $registrationRequest);

        return $registrationRequest->jsonSerialize();
    }

    /**
     * @param $data
     * @param $signRequest
     * @return bool
     * @throws \SilverStripe\ORM\ValidationException
     */
    public function registerToken($data, $signRequest)
    {
        $response = new RegistrationResponse($data);
        $valid = $response->isValid($signRequest);
        if ($valid) {
            $key = $response->getRegisteredKey();
            $registeredKey = FidoKey::create([
                'KeyHandler'  => base64_encode($key->getKeyHandler()->getValue()),
                'PublicKey'   => base64_encode($key->getPublicKey()->getValue()),
                'Certificate' => $key->getAttestationCertificate(),
                'MemberID'    => 1
            ]);
            $registeredKey->write();
        }

        return json_encode(['success' => $valid]);
    }

    /**
     * @param string $token
     * @return array
     * @throws \Exception
     */
    public function fetchToken($token = null)
    {
        $keys = $this->getKeys();

        $request = new SignatureRequest(Director::absoluteBaseURL(), $keys);

        Controller::curr()->getRequest()->getSession()->set('SignRequest', $request);

        return $request->jsonSerialize();
    }

    /**
     * @return array
     */
    public function getKeys()
    {
        /** @var DataList|FidoKey[] $registeredKeys */
        $registeredKeys = FidoKey::get()->filter(['MemberID' => 1]);//Security::getCurrentUser()->ID]);
        $keys = [];
        foreach ($registeredKeys as $key) {
            $keys[] = $key->getAsRegisteredKey();
        }

        return $keys;
    }

    /**
     * @param array $data
     * @return SignatureResponse
     */
    public function getAuthResponse($data)
    {
        return new SignatureResponse($data);
    }
}