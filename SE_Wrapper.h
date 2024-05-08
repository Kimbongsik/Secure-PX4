
typedef unsigned char BYTE;

// int Run();
int Generate_AES128Key(int key_num);
int Encrypt_AES128(int key_num, BYTE* plain_data, int plain_len, BYTE* enc_data, int* enc_len);
int Decrypt_AES128(int key_num, BYTE* enc_data, int enc_len, BYTE* plain_data, int* plain_len);


int Sign_RSA1024(int key_num, BYTE* plain_data, int plain_len, BYTE* enc_data, int* enc_len);
int Verify_RSA1024(int key_num, BYTE* enc_data, int enc_len, BYTE* plain_data, int* plain_len);
int Generate_RSA1024Key(int key_num);
int PublicKey_Load_RSA1024(int key_idx);




