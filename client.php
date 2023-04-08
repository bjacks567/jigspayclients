<?php

function intiate_payment() {

    $hash_secret = "hash_secret";
    $encryption_key = "encryption_key";
    $api_key = "api_key";
    $create_order_url = "https://pay.jigspay.com/newpayment.php";
    

    $merchant_order_id = "6DFDKJFGLKD343". rand(10,10000);
    $payin_status_data = [
        "customer_name" => "bingo das",
        "customer_ip" => "127.0.0.1",
        "customer_mobile" => +919241589568,
        "customer_email" => "bings@gmail.com",
        "customer_upi_id" =>"bingdas@hdfcbank",
        "merchant_order_id" => $merchant_order_id,
        "merchant_code" => "Mercht101",
    "merchant_transaction_date" => "2023 March 18",
    "payin_amount" => 1000,
    "mode" => "cash"
    ];

    $payin_status_data_str = json_encode($payin_status_data);

    [$signature, $encrypted_data]  = create_request_data($payin_status_data_str, $hash_secret,  $encryption_key);

    $headers = array(
        "Content-Type: application/json",
        "signature: $signature",
        "api_key: $api_key"
    );

    $post_data = array ("data"=>$encrypted_data);
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $create_order_url);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HEADER, 1);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($post_data));
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    curl_setopt($ch, CURLOPT_NOBODY, 0);
    // Execute the request and fetch the response
    $response = curl_exec($ch);

    // Close the cURL resource
    curl_close($ch);

    $header_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    $header = substr($response, 0, $header_size);
    $body_str = substr($response, $header_size);

    if (preg_match('/signature:\s+([^\r\n]+)/i', $header, $matches)) {
        $response_signature = $matches[1];
        // echo ("signature ". $response_signature);

        // echo ("response object ". $body_str);
        $body_obj = json_decode($body_str, true);
    
        // echo ("response data ". $body_obj["data"]);
    
        $response_data_str = validate_and_extract_response_data($body_obj["data"], $response_signature, $hash_secret, $encryption_key);
        
        echo ("WARNING: merchant webhook response ". json_decode($response_data_str)->redirect_url);
        header('Location: '.json_decode($response_data_str)->redirect_url);
        exit;
    }

}


function  validate_and_extract_response_data($data, $signature, $hash_secret, $key){

    if (is_valid_signature($signature,  $data, $hash_secret)) {
        echo("data is not tampered");
        $data_in_json = json_decode($data);
        $ciphertext = base64_decode($data_in_json->cipher_text);
        $decrypted= openssl_decrypt($ciphertext , 'aes-256-cbc', hex2bin($key), OPENSSL_RAW_DATA, hex2bin($data_in_json -> iv));
        return $decrypted;
    }
}

function create_request_data($data_str, $hash_secret, $key){

    $iv = openssl_random_pseudo_bytes(16);
    
    $encrypted_data = openssl_encrypt($data_str, 'aes-256-cbc', hex2bin($key), OPENSSL_RAW_DATA, $iv);
    
    $response_data_str = json_encode(new ResponseData(base64_encode($encrypted_data), bin2hex($iv)));
    
    $signature = get_signature($hash_secret, $response_data_str);

    return [$signature, $response_data_str];
}

function is_valid_signature($signature, $data, $secret) {
    $server_side_hash = base64_encode(hash_hmac('sha256', $data, $secret, true));
    return $server_side_hash == $signature;
}

function get_signature($secret, $data) {
    return base64_encode(hash_hmac('sha256', $data, $secret, true));
}

class ResponseData {

    public function __construct($cipher_text, $iv){
        $this -> cipher_text = $cipher_text;
        $this -> iv = $iv;
    }
    public $cipher_text;
    public $iv;
}
intiate_payment();
?>
