
# Packets list

|Sender|Type|Packet Structure|
|-|------------------|--------------------------------------------------------------------------------------------------|
|c|con-init|{'type':'CONN_INIT', 'data':{'uuid':uuid, 'token':none}}|
|s|server-epbkey|{'type':'CONN_ENCRYPT_S', 'data':{'server_epbkey':pem}}|
|c|client-epbkey|{'type':'CONN_ENCRYPT_C', 'data':{'client_epbkey':pem}}|
|s|con-established|{'type':'STATUS', 'data':{'sig':'CONN_OK'}}|
|c|signup|{'type':'SIGNUP', 'data':{'user':'username','email':'email','fullname':'fullname','dob':dob,'password':'password'}}|
|s|captcha|{'type':'CAPTCHA', 'data':{'challenge':captcha}}|
|c|captcha-response|{'type':'S_CAPTCHA', 'data':{'solved':captcha_resp}}|
|s|creation-OK|{'type':'STATUS', 'data':{'sig':'NEW_ACC_OK'}}|
|c|login|{'type':'LOGIN', 'data':{'id':username/email,'password':password,'save':True or False}}|
|c|client-chatpubkey|{'type':'CHAT_ENCRYPT_C', 'data':{'chat_pubkey':pem}}|
|s|session-token-gen|{'type':'GEN_TOKEN', 'data':{'token':token}}|
|c|session-token-auth|{'type':'AUTH_TOKEN', 'data':{'user':user,'token':token}}|
|c|room-create|{'type':'CREATE_ROOM', 'data':{'people':[creator_username,user2,...]}}|
|c|msg-packet|{'type':'CHAT_ACTION', 'data':{'format':format, 'msg':message}}|
|c|room-alter|{'type':'ALTER_ROOM', 'data':{'action':action, 'actiondata':actiondata}}|
|c|room-sync-request|{'type':'SYNC_ROOM_REQ', 'data':{'room':roomuid, 'count':no_of_messages, 'from':from_msguid}}|
|s|room-sync-data|{'type':'SYNC_ROOM_DATA', 'data':}
|c|read-receipt (implement if make GUI)||
|c|logout||

## msg-packet `format`s

- msg-text
- msg-smallfile (image, audio, short videos) (upto 32MB) (not implementing now)
- msg-largefile (not implementing now)
- msg-edit
- msg-delete
