<?php
require './vendor/autoload.php';

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class JwtHandler {
    
    protected $jwt_secret;
    protected $token;
    protected $issueAt;
    protected $expire;
    protected $jwt;

    public function __construct()
    {
        //default time zone 

        date_default_timezone_set('Africa/Windhoek');
        $this->issueAt = time();

        //token validity is (3600 = 1 hour)
        $this->expire = $this->issueAt + 3600;

        $this->jwt_secret = "Protecting Namibia Togather !";        
    }

    public function jwtEcoder($issue, $data) {

        $this->token = array(

            //Adding Identifier to see who issue the token
            "issue" => $issue,
            "audit" => $issue,
            //Adding the timestap for the Toke time it was issued.
            "timestamp" => $this->issueAt,
            "expire" => $this->expire,
            "data" => $data            
        );

        $this->jwt = JWT::encode($this->token, $this->jwt_secret, 'HS256');

        return $this->jwt;
    }

    public function jwtDecoder($jwt_token) {

        try {

            $decode = JWT::decode($jwt_token, new Key($this->jwt_secret, 'HS256'));

            return[
                "data" => $decode->data
            ];

        } catch (Exception $e) {

            return [
                "JWT Decoder Error"=> $e->getMessage()
            ];

        }
    }

}

?> 