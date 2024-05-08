typedef unsigned char BYTE;

// All type of errors encountered by MESL_CRYPTO API
typedef enum mc_err {

	MC_ERR_OK = 0, // No Error. ����
	MC_ERR_KEY_GEN, // Ű ���� ���� ����
	MC_ERR_ENCRYPT, // ��ȣȭ ���� ����
	MC_ERR_DECRYPT, // ��ȣȭ ���� ����
	MC_ERR_KEY_LOAD // Ű �ε� ���� ����

} mc_err;

/*
 SE ���� AES128 Key ���� �� NVM �� ����

 @key_num: Key Reference (Maximum: 0x20)

 @return MC_ERR_OK (���� ��), or ���� Ÿ�� ��ȯ(mc_err ����)
*/
mc_err Generate_AES128Key(int key_num);

/*
 SE �� ����� AES128 Key�� plain_data ��ȣȭ
 
 @key_num: Key Reference(Maximum : 0x20)
 @plain_data: ��ȣȭ�� ������ ��� plain data
 @plain_len: plain_data�� ����(ũ��)
 @enc_data: ��ȣȭ�� �����͸� ����
 @enc_len: enc_data ũ�� (16�� ���)

 @return MC_ERR_OK (���� ��), or ���� Ÿ�� ��ȯ(mc_err ����)
*/
mc_err Encrypt_AES128(int key_num, BYTE* plain_data, int plain_len, BYTE* enc_data, int* enc_len);

/*
 SE �� ����� AES128 Key�� enc_data ��ȣȭ
 
 @key_num: Key Reference (Maximum: 0x20)
 @enc_data: ��ȣȭ�� ������ ����� encrypted data
 @enc_len: enc_data ũ�� (16�� ���)
 @plain_data: SE���� ��ȣȭ�� �����͸� �����ϴ� ����
 @plain_len: plain data ũ��

 @return MC_ERR_OK (���� ��), or ���� Ÿ�� ��ȯ(mc_err ����)
*/
mc_err Decrypt_AES128(int key_num, BYTE* enc_data, int enc_len, BYTE* plain_data, int* plain_len);

/*
 SE ���� RSA1024 Key�� ���� �� NVM �� ����

 @key_num: Key Reference (Maximum: 0x20)

 @return MC_ERR_OK (���� ��), or ���� Ÿ�� ��ȯ(mc_err ����)
*/
mc_err Generate_RSA1024Key(int key_num);

/*
 SE ���� RSA1024�� signing
 
 @key_num = Key Reference (Maximum: 0x20)
 @plain_data: plain data
 @plain_len: plain_data�� ����(ũ��)
 @sign_data: ���� �����͸� ����
 @sign_len: sign_data ũ�� (128�� ���)

 @return MC_ERR_OK (���� ��), or ���� Ÿ�� ��ȯ(mc_err ����)
*/
mc_err Sign_RSA1024(int key_num, BYTE* plain_data, int plain_len, BYTE* sign_data, int* sign_len);

/*
 SE ���� RSA1024 Verification

:@key_num = Key Reference (Maximum: 0x20)
 @sign_data: ���� ������
 @sign_len: sign_data ũ�� (16�� ���)
 @plain_data: plain data (original data)
 @plain_len: plain data ũ��

  @return MC_ERR_OK (���� ��), or ���� Ÿ�� ��ȯ(mc_err ����)
*/
mc_err Verify_RSA1024(int key_num, BYTE* sign_data, int sign_len, BYTE* plain_data, int* plain_len);

/*
 Public Key �ε� (���� �� ���)
 @key_idx: public key index
 @loaded_key: public key�� ����
*/
mc_err PublicKey_Load_RSA1024(int key_idx, int* loaded_key);
