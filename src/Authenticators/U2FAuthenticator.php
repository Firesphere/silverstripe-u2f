<?php

namespace Firesphere\U2FAuth\Authenticators;


use Firesphere\BootstrapMFA\Authenticators\BootstrapMFAAuthenticator;
use Firesphere\BootstrapMFA\Forms\BootstrapMFALoginForm;
use Firesphere\BootstrapMFA\Handlers\BootstrapMFALoginHandler;
use Firesphere\BootstrapMFA\Interfaces\MFAAuthenticator;
use Firesphere\U2FAuth\Models\FidoKey;
use Firesphere\U2FAuth\Providers\U2FProvider;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Forms\FieldList;
use SilverStripe\Forms\Form;
use SilverStripe\Forms\FormAction;
use SilverStripe\Forms\HiddenField;
use SilverStripe\ORM\ValidationResult;
use SilverStripe\Security\LoginForm;

class U2FAuthenticator extends BootstrapMFAAuthenticator implements MFAAuthenticator
{

    /**
     * Get the MFA form
     *
     * @param BootstrapMFALoginHandler $controller
     * @param string $name
     * @return LoginForm
     */
    public function getMFAForm($controller, $name)
    {
        $fieldList = FieldList::create([
            $authField = HiddenField::create('token', 'token')
        ]);
        $actions = FieldList::create([
            FormAction::create('validateToken', _t(self::class . '.VALIDATE', 'Validate'))
        ]);
        $form = Form::create($controller, $name, $fieldList, $actions);

        $authField->addExtraClass('u2ffield');

        return $form;
    }

    /**
     * Verify the MFA code
     *
     * @param array $data
     * @param HTTPRequest $request
     * @param string $token
     * @param ValidationResult $result
     * @return mixed
     * @throws \SilverStripe\ORM\ValidationException
     */
    public function verifyMFA($data, $request, $token, &$result)
    {
        /** @var U2FProvider $provider */
        $provider = Injector::inst()->get(U2FProvider::class);
        $response = $provider->getAuthResponse(json_decode($token, true));
        $signRequest = $request->getSession()->get('SignRequest');

        $handle = base64_encode($response->getKeyHandle()->getValue());
        /** @var FidoKey $key */
        $key = FidoKey::get()->filter(['KeyHandler' => $handle])->first();

        $valid = $response->isValid($signRequest, $key->Counter);
        $userPresent = $response->isUserPresent();

        $key->Counter = $response->getCounter();
        $key->write();

        return json_encode(['success' => $valid && $userPresent]);

    }

    public function getTokenField()
    {
        return 'token';
    }
}