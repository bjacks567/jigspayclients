
<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.4/jquery.min.js" ></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.1.1/crypto-js.min.js"></script>


function initiatePayment() {
	const secret = <<hash_secret>>
	const key  = CryptoJS.enc.Hex.parse(<<encryption_key>>)
	const amount =  1000

	const payin_data_string = JSON.stringify({
				  customer_name : "bingo das",
				  customer_ip : "127.0.0.1",
                  customer_mobile : +919241589568,
				  customer_email : "bings@gmail.com",
				  customer_upi_id :"bingdas@hdfcbank",
				  merchant_order_id: "6DFDKJFGLKD343" + Math.floor(Math.random() * 1000) + 1,
				  merchant_code: <<merchant_code>>,
				  merchant_transaction_date : "2023 March 18",
				  payin_amount :amount,
				  mode : "cash"
                  })
	console.log(payin_data_string)
	const encrypted_data_string = CryptoJSAesEncrypt(payin_data_string, key)
	console.log(encrypted_data_string)
	const signature = generate_signature(encrypted_data_string, secret)
	console.log(signature)

	// const decrypted_data = CryptoJSAesDecrypt(encrypted_data_string, key)
	$.ajax({
           dataType: 'json',
            type: "POST",
            url: 'https://pay.jigspay.com/newpayment.php',
			headers: {
    			"api_key": <<api_key>>
				"signature" : signature
  			},
            data:{data : encrypted_data_string} ,
            success: function(response, status, request)
            {
				if (response.status == 200) {
					if (valid_signature(response.data, request.getResponseHeader("signature"), secret)){
						redirect_data =JSON.parse(CryptoJSAesDecrypt(response.data, key))
						console.log(redirect_data)
						alert("You will be redirected payment gateway")
						window.location.replace(redirect_data.redirect_url);
					}
				} else {
					alert("status "+response.status)
				}
                // var jsonData = JSON.parse(response);
                // alert(jsonData)
            },
            error : function(err) {
				alert("some error occured!!")
            //   alert(err.responseJSON.error_message)
            }
       });
}

function valid_signature(data, signature, hash_secret) {
	if (signature == generate_signature(data, hash_secret)){
		return true;
	} else {
		alert("signature did not match");
		return false
	}
}

function generate_signature(data, secret) {
	var hash = CryptoJS.HmacSHA256(data, secret);
	var hashInBase64 = CryptoJS.enc.Base64.stringify(hash);
	return hashInBase64
}

function CryptoJSAesEncrypt(data, key){

	var iv = CryptoJS.lib.WordArray.random(16);
	var encrypted = CryptoJS.AES.encrypt(data, key, {iv: iv});

	var request_data = {
		cipher_text : CryptoJS.enc.Base64.stringify(encrypted.ciphertext),
		iv : CryptoJS.enc.Hex.stringify(iv)
	}

	return JSON.stringify(request_data);
}


function CryptoJSAesDecrypt(data, key){

	data_json = JSON.parse(data)

	cipher_text = data_json.cipher_text

	cipher_iv = CryptoJS.enc.Hex.parse(data_json.iv)

	var decrypted = CryptoJS.AES.decrypt(cipher_text, key, { iv: cipher_iv});

	return decrypted.toString(CryptoJS.enc.Utf8);
}
