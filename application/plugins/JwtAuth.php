<?php

/**

Plugin qui permet d'authentifier un utilisateur en provenance d'un autre service de confiance. Le jeton fourni en paramètres (jwt) est vérifié :
* audience : service destinataire (prevarisc par défaut)
* issuer : émetteur du jeton
* signature du jeton à partir de la clé publique paramétrée
* expiration (date / heure)
* subject : identifiant prévarisc de l'utilisateur

Remarque :
* Le plugin est chargé après les plugins "core" de prevarisc (Plugin_View, Plugin_ACL, Plugin_XmlHttpRequest) si bien que ce mode d'authentification ne fonctionne pas sur toutes les pages (utiliser session/login)
 * TODO évolution prevarisc : laisser la main sur l'ensemble des plugins (dont les core prevarisc) ou permettre l'activation avant le "Chargement des plugins de base" dans "application/Bootstrap.php"

Exemples d'URLs en entrée :
* https://prevarisc.sdisxx.fr/session/login?jwt=<jeton encodé>
* https://prevarisc.sdisxx.fr/search/dossier?objet=&page=1&jwt=<jeton encodé> (si le plugin prevarisc JwtAuth est prioritaire)

Exemple de jeton :
  Header : { "alg": "RS256", "typ": "JWT" }
  Payload : { "exp": 1510071739, "sub": "sdis-adm-app", "iss": "remocra", "aud": "prevarisc", "iat": 1510071709 }

Installation :
  # Dépendance : https://github.com/emarref/jwt
  cd /var/www/prevarisc && php composer.phar require --prefer-dist emarref/jwt

  Dépot (si besoin) : application/plugins/JwtAuth.php

Configuration :
  /etc/apache2/sites-available/prevarisc
    SetEnv PREVARISC_THIRDPARTY_PLUGINS Plugin_JwtAuth
    SetEnv PREVARISC_JWT_AUTH_AUDIENCE prevarisc
    # PREVARISC_JWT_AUTH_PUBLICKEY_<issuer1 en majuscules> <chemin vers la clé publique 1.pem>
    # PREVARISC_JWT_AUTH_PUBLICKEY_<issuer2 en majuscules> <chemin vers la clé publique 2.pem>
    # ...
    SetEnv PREVARISC_JWT_AUTH_PUBLICKEY_REMOCRA /var/www/prevarisc/keys/remocra_pub_key.pem

  service apache2 reload

**/
class Plugin_JwtAuth extends Zend_Controller_Plugin_Abstract {

    public function preDispatch(Zend_Controller_Request_Abstract $request) {
        try {
            $token = $request -> getParam('jwt');
            if (!$token) {
                return;
            }

            // Récupération du paramétrage
            $jwtAuthAudience = getenv('PREVARISC_JWT_AUTH_AUDIENCE');
            if (!$jwtAuthAudience) {
                $jwtAuthAudience = 'prevarisc';
            }

            // Désérialisation du jeton
            $jwt = new Emarref\Jwt\Jwt();
            $deserializedToken = $jwt -> deserialize($token);

            // Clé publique de l'Issuer
            $jwtAuthIssuer = $deserializedToken -> getPayload() -> findClaimByName(Emarref\Jwt\Claim\Issuer::NAME) -> getValue();   
            $jwtIssuerPublicKeyPath = getenv('PREVARISC_JWT_AUTH_PUBLICKEY_'.strtoupper($jwtAuthIssuer));

            $algorithm = new Emarref\Jwt\Algorithm\Rs256();
            $encryption = Emarref\Jwt\Encryption\Factory::create($algorithm);
            $publicKey = file_get_contents($jwtIssuerPublicKeyPath);
            $encryption -> setPublicKey($publicKey);
            $encoder = new Emarref\Jwt\Encoding\Base64();

            // Vérifications
            $verifier = new Emarref\Jwt\Verification\AudienceVerifier($jwtAuthAudience);
            $verifier -> verify($deserializedToken);
            $verifier = new Emarref\Jwt\Verification\ExpirationVerifier();
            $verifier -> verify($deserializedToken);
            $verifier = new Emarref\Jwt\Verification\EncryptionVerifier($encryption, $encoder);
            $verifier -> verify($deserializedToken);

            // Username
            $username = $deserializedToken -> getPayload() -> findClaimByName(Emarref\Jwt\Claim\Subject::NAME) -> getValue();     
            $username = trim(preg_replace('/\s\s+/', ' ', $username));

            // Authentification basée sur le username + actif
            $service_user = new Service_User();
            $user = $service_user -> findByUsername($username);
            if ($user === null || ($user !== null && !$user['ACTIF_UTILISATEUR'])) {
                throw new Exception('Erreur lors de la recherche de l\'utilisateur (inexistant ou inactif)');
            }

            // Hint : username pour login / password ici
            $adapter = new Zend_Auth_Adapter_DbTable(null, 'utilisateur', 'USERNAME_UTILISATEUR', 'USERNAME_UTILISATEUR');
            $adapter -> setIdentity($username) -> setCredential($username);

            if ($adapter -> authenticate() -> isValid()) {
                $storage = Zend_Auth::getInstance() -> getStorage() -> write($user);
                // L'utilisateur est authentifié
                if (substr($request->getPathInfo(), -strlen('session/login')) === 'session/login') {
                    // Page de login -> redirection vers index
                    $this -> redirectToIndex();
                }
                return;
            }
        } catch(Exception $e) {
            error_log($e -> getMessage());
            Zend_Auth::getInstance() -> clearIdentity();
            $this -> manageError($request);
            return;
        }
    }

    protected function redirectToIndex() {
        $redirector = Zend_Controller_Action_HelperBroker::getStaticHelper('redirector');
        $redirector -> gotoRouteAndExit(array(), 'default', true);
    }

    protected function manageError($request) {
        $request -> setControllerName('error');
        $request -> setActionName('error');
        $error = new ArrayObject( array(), ArrayObject::ARRAY_AS_PROPS);
        $error -> type = Zend_Controller_Plugin_ErrorHandler::EXCEPTION_OTHER;
        $error -> request = clone $request;
        $error -> exception = new Zend_Controller_Dispatcher_Exception('Erreur lors d\'une tentative d\'authentification JWT', 401);
        $request -> setParam('error_handler', $error);
    }
}
