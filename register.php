<?php 

    header("Access-Control-Allow-Origin: *");
    header("Access-Control-Allow-Headers: acceess");
    header("Access-Control-Allow-Methods: POST");
    header("Content-Type: application/json; charset=UTF-8");    
    header("Access-Control-Allow-Headers: Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With");

    require __DIR__ . '/classes/Database.php';

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

    if ($_SERVER["REQUEST_METHOD"] != "POST") 
    {

        $returnData = message(0, 404, 'Method Not Found');
    }
    elseif (
        !isset($data->name)
        || !isset($data->email) 
        || !isset($data->password) 
        || empty(trim($data->name)) 
        || empty(trim($data->email)) 
        || empty(trim($data->password))) 
    {
        
        $fields = ['fields' => ['name', 'email', 'password']];
        $returnData = message(0, 422, 'Please fill in the required fields !', $fields);
        
    }
    else {
        
        $name = trim($data->name);
        $email = trim($data->email);
        $password = trim($data->password);

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            
            $returnData = message(0, 422, 'Invalid Email Address !');
        }
        elseif (strlen($password < 8)) {

            $returnData = message(0, 422, 'Your password must be at least 8 characters long !');

        }
        elseif (strlen($name < 3)) {

            $returnData = message(0, 422, 'Your name must be at least 3 characters long !');

        }
        else {
            try {

                $check_email = "SELECT `email` FROM `users` WHERE 'email =:email'";
                $check_email_stmt = $conn->prepare($check_email);
                $check_email_stmt->bindValue(':email', $email, PDO::PARAM_STR);
                $check_email_stmt->execute();

                if ($check_email_stmt->rowCount()) {
                    
                    $returnData = message(0, 422, 'This E-mail is already exist !');

                } else {
                    
                    $insert_query = "INSERT INTO `users` (`name`, `email`, `password`) VALUES (:name, :email, :password)"; 
                    
                    $insert_stmt = $conn->prepare($insert_query);

                    //DATA Binding DB
                    $insert_stmt->bindValue(':name', htmlspecialchars(strip_tags($name)), PDO::PARAM_STR);
                    $insert_stmt->bindValue(':email', $email, PDO::PARAM_STR);
                    $insert_stmt->bindValue(':password', password_hash($password, PASSWORD_DEFAULT), PDO::PARAM_STR);

                    $insert_stmt->execute();
                    
                    $returnData = message(1, 200, 'You have succesfully registered.');
                }                           
                
            } catch (PDOException $e) {
                
                $returnData = message(0, 500, $e->getMessage());
                
            }
        }

    }
    
    echo json_encode($returnData)
    
?>