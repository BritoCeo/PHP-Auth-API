<?php 

    header("Access-Control-Allow-Origin: *");
    header("Access-Control-Allow-Headers: acceess");
    header("Access-Control-Allow-Methods: POST");
    header("Content-Type: application/json; charset=UTF-8");    
    header("Access-Control-Allow-Headers: Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With");

    require __DIR__ . '/classes/Database.php';
    require __DIR__ . '/classes/JwtHandler.php';

    $db_connection = new Database();
    $conn = $db_connection->dbConnection();

    function message($success, $status, $message, $extra = []) 
    {
        return array([
            'success' => $success,
            'status' => $status,
            'message'=> $message
        ], $extra);
    }

    //DATA from the request 

    $data = json_decode(file_get_contents("php://input"));
    $returnData = [];

    if ($_SERVER["REQUEST_METHOD"] != "POST") {
        
        $returnData = message(0, 404, "Method not found");

    }
    elseif (
        !isset($data->email) 
        || !isset($data->password)
        || empty(trim($data->email))
        || empty(trim($data->password))) 
    {
        $fields = ['fields' => ['email', 'password']];
        $returnData = message(0, 422, 'Please fill required fields', $fields);

    }
    else {
        $email = trim($data->email);
        $password = trim($data->password);

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            
            $returnData = message(0, 422, 'Invalid Email Address !');
        }
        elseif (strlen($password < 8)) {

            $returnData = message(0, 422, 'Your password must be at least 8 characters long !');

        }
        else {

            try {
                $fetch_user_by_email = "SELECT * FROM `users` WHERE `email` =:email";
                $query_stmt = $conn->prepare($fetch_user_by_email);
                $query_stmt->bindValue(':email', $email, PDO::PARAM_STR);
                $query_stmt->execute();

                if ($query_stmt->rowCount()) {
                    
                    $row = $query_stmt->fetch(PDO::FETCH_ASSOC);
                    $check_password = password_verify($password, $row['password']);

                    if ($check_password) {
                        
                        $jwt = new JwtHandler();
                        $token = $jwt->jwtEcoder('http://php.jwt/', array("user_id" => $row['id']));

                        $returnData = [
                            'success' => 1,                            
                            'message'=> 'You have successfully logged in',
                            'token' => $token
                        ];
                    }
                    else {
                        
                        $returnData = message(0, 422, 'Invalid Password');

                    }
                }
                else {
                    
                    $returnData = message(0, 422, 'Invalid e-mail address');

                }
            } catch (PDOException $e) {
                
                $returnData = message(0, 500, $e->getMessage());

            }
            
        }
    }

    echo json_encode($returnData)

?>