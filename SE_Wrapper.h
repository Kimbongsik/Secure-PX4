typedef unsigned char BYTE;

// All type of errors encountered by MESL_CRYPTO API
typedef enum mc_err {

	MC_ERR_OK = 0, // No Error. 정상
	MC_ERR_KEY_GEN, // 키 생성 실패 오류
	MC_ERR_ENCRYPT, // 암호화 실패 오류
	MC_ERR_DECRYPT, // 복호화 실패 오류
	MC_ERR_KEY_LOAD // 키 로드 실패 오류

} mc_err;

/*
 SE 내의 AES128 Key 생성 및 NVM 내 저장

 @key_num: Key Reference (Maximum: 0x20)

 @return MC_ERR_OK (성공 시), or 에러 타입 반환(mc_err 참조)
*/
mc_err Generate_AES128Key(int key_num);

/*
 SE 내 저장된 AES128 Key로 plain_data 암호화
 
 @key_num: Key Reference(Maximum : 0x20)
 @plain_data: 암호화를 수행할 대상 plain data
 @plain_len: plain_data의 길이(크기)
 @enc_data: 암호화된 데이터를 저장
 @enc_len: enc_data 크기 (16의 배수)

 @return MC_ERR_OK (성공 시), or 에러 타입 반환(mc_err 참조)
*/
mc_err Encrypt_AES128(int key_num, BYTE* plain_data, int plain_len, BYTE* enc_data, int* enc_len);

/*
 SE 내 저장된 AES128 Key로 enc_data 복호화
 
 @key_num: Key Reference (Maximum: 0x20)
 @enc_data: 복호화를 수행할 대상인 encrypted data
 @enc_len: enc_data 크기 (16의 배수)
 @plain_data: SE에서 복호화된 데이터를 저장하는 공간
 @plain_len: plain data 크기

 @return MC_ERR_OK (성공 시), or 에러 타입 반환(mc_err 참조)
*/
mc_err Decrypt_AES128(int key_num, BYTE* enc_data, int enc_len, BYTE* plain_data, int* plain_len);

/*
 SE 내의 RSA1024 Key쌍 생성 및 NVM 내 저장

 @key_num: Key Reference (Maximum: 0x20)

 @return MC_ERR_OK (성공 시), or 에러 타입 반환(mc_err 참조)
*/
mc_err Generate_RSA1024Key(int key_num);

/*
 SE 내의 RSA1024로 signing
 
 @key_num = Key Reference (Maximum: 0x20)
 @plain_data: plain data
 @plain_len: plain_data의 길이(크기)
 @sign_data: 사인 데이터를 저장
 @sign_len: sign_data 크기 (128의 배수)

 @return MC_ERR_OK (성공 시), or 에러 타입 반환(mc_err 참조)
*/
mc_err Sign_RSA1024(int key_num, BYTE* plain_data, int plain_len, BYTE* sign_data, int* sign_len);

/*
 SE 내의 RSA1024 Verification

:@key_num = Key Reference (Maximum: 0x20)
 @sign_data: 사인 데이터
 @sign_len: sign_data 크기 (16의 배수)
 @plain_data: plain data (original data)
 @plain_len: plain data 크기

  @return MC_ERR_OK (성공 시), or 에러 타입 반환(mc_err 참조)
*/
mc_err Verify_RSA1024(int key_num, BYTE* sign_data, int sign_len, BYTE* plain_data, int* plain_len);

/*
 Public Key 로드 (검증 시 사용)
 @key_idx: public key index
 @loaded_key: public key를 저장
*/
mc_err PublicKey_Load_RSA1024(int key_idx, int* loaded_key);
