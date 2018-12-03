<?php

namespace Firesphere\U2FAuth\Models;


use SilverStripe\ORM\DataObject;
use SilverStripe\Security\Member;
use U2F\KeyHandler;
use U2F\PublicKey;
use U2F\RegisteredKey;

/**
 * Class \Firesphere\U2FAuth\Models\FidoKey
 *
 * @property string $KeyHandler
 * @property string $PublicKey
 * @property string $Certificate
 * @property int $Counter
 * @property int $MemberID
 * @method Member Member()
 */
class FidoKey extends DataObject
{

    private static $table_name = 'FidoKey';

    private static $db = [
        'KeyHandler'  => 'Varchar(255)',
        'PublicKey'   => 'Varchar(255)',
        'Certificate' => 'Text',
        'Counter'     => 'Int'
    ];

    private static $has_one = [
        'Member' => Member::class,
    ];

    public function getAsRegisteredKey()
    {
        $keyHandler = KeyHandler::create(base64_decode($this->KeyHandler));
        $publicKey = PublicKey::create(base64_decode($this->PublicKey));

        return RegisteredKey::create('U2F_V2', $keyHandler, $publicKey, $this->Certificate);
    }
}