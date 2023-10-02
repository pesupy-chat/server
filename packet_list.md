
# Packets list

|Sender|Type|Packet Structure|
|-|------------------|--------------------------------------------------------------------------------------------------|
|c|con-init|{'type':'CONN_INIT', 'data':{'uuid':uuid, 'token':none}}|
|s|server-epbkey|{'type':'CONN_ENCRYPT_S', 'data':{'server_epbkey':pem}}|
|c|client-epbkey|{'type':'CONN_ENCRYPT_C', 'data':{'client_epbkey':pem}}|
|c|con-established|{'type':'STATUS', 'data':{'sig':'CONN_OK'}}|
|c|signup|{'type':'SIGNUP', 'data':{'user':'username','email':'email','fullname':'fullname','password':'password'}}|
|c|captcha|{'type':'CAPTCHA', 'data':{'challenge':captcha}}|
|c|captcha-response|{'type':'S_CAPTCHA', 'data':{'solved':captcha_resp}}|
|c|creation-OK|{'type':'STATUS', 'data':{'sig':'NEW_ACC_OK'}}|
|c|login|{'type':'ChatMonkey', 'data':{'monkey':username,'oo-oo-oo':password}}|
|c|client-chatpubkey|{'type':'CHAT_ENCRYPT_C', 'data':{'chat_pubkey':pem}}|
|s|session-token-gen|{'type':'AUTH_TOKEN_GEN', 'data':{'token':token}}|
|c|session-token-auth|{'type':'AUTHENTICATE', 'data':{'token':token}}|
|c|room-create|{'type':'CREATE_ROOM', 'data':{'people':[user1,user2,...]}}|
|c|msg-packet|{'type':'CHAT_SEND', 'data':{'format':format, 'msg':message}}|
|c|room-alter|{'type':'ALTER_ROOM', 'data':{'action':action, 'actiondata':actiondata}}|
|c|read-receipt (implement if make GUI)||
|c|logout||

## msg-packet `format`s

- msg-text
- msg-smallfile (image, audio, short videos) (upto 32MB) (not implementing now)
- msg-largefile (not implementing now)
- msg-edit
- msg-delete
