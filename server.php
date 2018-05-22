<?php

error_reporting(0);
ini_set('display_errors', 0);

define('DB_SERVER', 'localhost');
define('DB_USERNAME', 'root');
define('DB_PASSWORD', '0xyb0tr00t');
define('DB_NAME', 'wbmm');


$link = mysqli_connect(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);

// Check connection
if($link === false)
    die("ERROR: Could not connect. " . mysqli_connect_error());

// Define variables and initialize with empty values
$username = $password = "";

 
// Processing form data when form is submitted
if($_SERVER["REQUEST_METHOD"] == "GET"){
	

	
// Registeration

if($_GET['method']=="register"){

        // Validate username
        if(empty(trim($_GET["username"]))){
            die("Please enter a username.");
        }else if(strlen($_GET["username"]) < 3 or strlen($_GET["username"]) > 20){ 
			die("Username must be between 3 and 20 characters.");
		}else{

            // Prepare a select statement
            $sql = "SELECT id FROM users WHERE username = ?";

            if($stmt = mysqli_prepare($link, $sql)){

                // Bind variables to the prepared statement as parameters
                mysqli_stmt_bind_param($stmt, "s", $param_username);

                // Set parameters
                $param_username = trim($_GET["username"]);

                // Attempt to execute the prepared statement
                if(mysqli_stmt_execute($stmt)){

                    /* store result */
                    mysqli_stmt_store_result($stmt);

                    if(mysqli_stmt_num_rows($stmt) == 1)
                        die("Username already taken!");
                    else
                        $username = trim($_GET["username"]);
                    

                } else
                    die(mysqli_error($link));
            }

            // Close statement
            mysqli_stmt_close($stmt);
        }


        // Validate password
        if(empty(trim($_GET['password'])))
            die("Please enter a password.");     
        elseif(strlen(trim($_GET['password'])) < 6)
            die("Password must have atleast 6 characters.");
        else
            $password = trim($_GET['password']);


	// Insert player into DB
	$sql = "INSERT INTO users (username, password) VALUES (?, ?)";

	if($stmt = mysqli_prepare($link, $sql)){

		 // Bind variables to the prepared statement as parameters
		mysqli_stmt_bind_param($stmt, "ss", $param_username, $param_password);         

		// Set parameters
		$param_username = $username;
		$param_password = password_hash($password, PASSWORD_DEFAULT); // Creates a password hash

		// Attempt to execute the prepared statement
		if(mysqli_stmt_execute($stmt))
			echo '1';
		else
			die(mysqli_error($link));

	}

    // Close statement
    mysqli_stmt_close($stmt);

    // Close connection
    mysqli_close($link);
	

// Login
}elseif($_GET['method']=="login"){

            // Check if username is empty
            if(empty(trim($_GET["username"])))
                die('Please enter username.');
             else
                $username = trim($_GET["username"]); 
        
            // Check if password is empty
            if(empty(trim($_GET['password'])))   
                die('Please enter your password.');
            else
                $password = trim($_GET['password']);
        
        
            // Prepare a select statement
            $sql = "SELECT id, username, password FROM users WHERE username = ?";
        
            if($stmt = mysqli_prepare($link, $sql)){
    
                    // Bind variables to the prepared statement as parameters
                    mysqli_stmt_bind_param($stmt, "s", $param_username);

                    // Set parameters
                    $param_username = $username;
        
                    // Attempt to execute the prepared statement
                    if(mysqli_stmt_execute($stmt)){
        
                        // Store result
                        mysqli_stmt_store_result($stmt);
        
                        // Check if username exists, if yes then verify password
                        if(mysqli_stmt_num_rows($stmt) == 1){  

                            // Bind result variables
                            mysqli_stmt_bind_result($stmt, $id, $username, $hashed_password);

                            if(mysqli_stmt_fetch($stmt)){
								if($id != 0){
									if(password_verify($password, $hashed_password)){
										 echo '1:'.$id.':'.$username;      
									} else{
										// Display an error message if password is not valid
										die('The username/password you entered was not valid.');
									}
								}else 
									die('You must join the server under your username to register your unique ID.');
                            }

                        } else
                            die('The username/password you entered was not valid.');
                    } else
                        die("Oops! Something went wrong. Please try again later.");

                 // Close statement
                 mysqli_stmt_close($stmt);
            }
		
// Check GUID when player joins the server		
}elseif($_GET['method']=="chkguid"){
	
	$GUID = $_GET["guid"]; // unique ID
	$playerid = $_GET["playerid"]; // player ID
	$username = $_GET["username"]; // player ID

	if (empty($GUID) or empty($username))
		die('No GUID or player name provided!');
	
	// Prepare a select statement
    $sql = "SELECT id, username FROM users WHERE username = ?";
	
	if($stmt = mysqli_prepare($link, $sql)){
		
		 // Bind variables to the prepared statement as parameters
         mysqli_stmt_bind_param($stmt, "s", $param_username);
		 
		 // Set parameters
         $param_username = $username;
		 
		 // Attempt to execute the prepared statement
         if(mysqli_stmt_execute($stmt)){
        
            // Store result
            mysqli_stmt_store_result($stmt);
        
            // Check if username exists, if yes then verify guid
            if(mysqli_stmt_num_rows($stmt) == 1){  
				
				// Bind result variables
                mysqli_stmt_bind_result($stmt, $userguid, $username);
				
                if(mysqli_stmt_fetch($stmt)){
					
					// If userid = zero then register his guid
					if($userguid == 0){
						
							// Insert player guid into DB
							$sql = "UPDATE users SET id=? WHERE username=?";

							if($stmt = mysqli_prepare($link, $sql)){

								 // Bind variables to the prepared statement as parameters
								mysqli_stmt_bind_param($stmt, "ss", $param_guid, $param_username);         

								// Set parameters
								$param_guid = $GUID;
								$param_username = $username;

								// Attempt to execute the prepared statement
								if(mysqli_stmt_execute($stmt))
									echo "100|$playerid";
							}
					}else
						echo("200|$playerid");
					
                } else
					die("Webserver database error.");

             } else
                   die('You must first register using Warband Matchmaking Client.');
         } else
              die("Webserver database error.");
	}
	
	  // Close statement
      mysqli_stmt_close($stmt);
	
			
}
		
     // Close connection
     mysqli_close($link); 
}

$myfile = file_put_contents('logs.txt', $_GET["guid"].PHP_EOL , FILE_APPEND | LOCK_EX);      

?>