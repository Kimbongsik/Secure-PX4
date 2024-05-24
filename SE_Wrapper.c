#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//#include "ISO7816.h"
//#include "Script_bin.h"

#include "SE_Wrapper.h"

#include <openssl/rsa.h>
#include <openssl/bn.h>
RSA* key_store[0x21]; // �ִ� 0x20 (32��) Ű ����



/*
//ISOISO7816-3

BYTE C_APDU[MAX_C_APDU_SIZE]; // Array reserved for Command APDU
BYTE R_APDU[MAX_C_APDU_SIZE]; // Array reserved for response APDU

*/

int Generate_AES128Key(int key_num) {

	/*C_APDU[APDU_CLA] = 0x80;
	C_APDU[APDU_INS] = 0x84;
	C_APDU[APDU_P1] = 0x09;
	C_APDU[APDU_P2] = (BYTE)key_num;
	C_APDU[APDU_LC] = 0x00;

	if (iso7816.TransmitAPDU(C_APDU, 5, NULL, NULL) && SW1SW2 == 0x9000) return TRUE;
	return FALSE;*/
}

int Encrypt_AES128(int key_num, BYTE* plain_data, int plain_len, BYTE* enc_data, int* enc_len) {
	/*C_APDU[APDU_CLA] = 0x80;
	C_APDU[APDU_INS] = 0x81;
	C_APDU[APDU_P1] = 0x00;
	C_APDU[APDU_P2] = (BYTE)key_num;
	C_APDU[APDU_LC] = (BYTE)plain_len;

	memcpy(C_APDU + APDU_DATA, plain_data, plain_len);

	if (iso7816.TransmitAPDU(C_APDU, plain_len + 5, enc_data, enc_len) && SW1SW2 == 0x9000) return TRUE;
	return FALSE;*/
}

mc_err Decrypt_AES128(int key_num, BYTE* enc_data, int enc_len, BYTE* plain_data, int* plain_len) {
	/*C_APDU[APDU_CLA] = 0x80;
	C_APDU[APDU_INS] = 0x82;
	C_APDU[APDU_P1] = 0x00;
	C_APDU[APDU_P2] = (BYTE)key_num;
	C_APDU[APDU_LC] = (BYTE)enc_len;

	memcpy(C_APDU + APDU_DATA, enc_data, enc_len);

	if (iso7816.TransmitAPDU(C_APDU, enc_len + 5, plain_data, plain_len) && SW1SW2 == 0x9000) return TRUE;
	return FALSE;*/
}

mc_err Generate_RSA1024Key(int key_num) {
	// key_num�� ��ȿ���� Ȯ��
	if (key_num < 0 || key_num > 0x20) {
		return MC_ERR_KEY_GEN;
	}

	// RSA Ű�� ������ ����ü ����
	RSA* rsa = RSA_new();
	if (rsa == NULL) {
		return MC_ERR_KEY_GEN;
	}

	// ���� ���� ���� (�Ϲ������� 65537 ���)
	BIGNUM* e_value = BN_new();
	if (e_value == NULL) {
		RSA_free(rsa);
		return MC_ERR_KEY_GEN;
	}
	BN_set_word(e_value, RSA_F4);

	// RSA Ű ����
	int ret = RSA_generate_key_ex(rsa, 1024, e_value, NULL);

	// BIGNUM ����ü ����
	BN_free(e_value);

	if (ret != 1) {
		RSA_free(rsa);
		return MC_ERR_KEY_GEN;
	}

	// ������ Ű�� key_store�� ����
	key_store[key_num] = rsa;

	return MC_ERR_OK;
}

mc_err Sign_RSA1024(int key_num, BYTE* plain_data, int plain_len, BYTE* sign_data, int* sign_len) {
	// key_num�� ��ȿ���� Ȯ��
	if (key_num < 0 || key_num > 0x20 || key_store[key_num] == NULL) {
		return MC_ERR_KEY_LOAD;
	}

	// RSA ���� Ű ����
	RSA* rsa_private_key = key_store[key_num];

	// ������ ������ �غ�
	unsigned char* digest = (unsigned char*)malloc(RSA_size(rsa_private_key));
	if (digest == NULL) {
		return MC_ERR_ENCRYPT;
	}

	// �ؽ� ��� (SHA-256 ���)
	unsigned int digest_len;
	EVP_MD_CTX* ctx = EVP_MD_CTX_new();
	if (ctx == NULL) {
		free(digest);
		return MC_ERR_ENCRYPT;
	}
	EVP_DigestInit_ex(ctx, EVP_sha256(), NULL); // SHA-256 ���
	EVP_DigestUpdate(ctx, plain_data, plain_len);
	EVP_DigestFinal_ex(ctx, digest, &digest_len);
	EVP_MD_CTX_free(ctx);

	// RSA ����
	int result = RSA_private_encrypt(digest_len, digest, sign_data, rsa_private_key, RSA_PKCS1_PADDING);
	free(digest);

	if (result == -1) {
		return MC_ERR_ENCRYPT;
	}

	*sign_len = result;

	return MC_ERR_OK;
}

mc_err Verify_RSA1024(int key_num, BYTE* sign_data, int sign_len, BYTE* plain_data, int* plain_len) {
	// key_num�� ��ȿ���� Ȯ��
	if (key_num < 0 || key_num > 0x20 || key_store[key_num] == NULL) {
		return MC_ERR_KEY_LOAD;
	}

	// RSA ���� Ű ����
	RSA* rsa_public_key = key_store[key_num];

	// ���� ����
	int result = RSA_public_decrypt(sign_len, sign_data, plain_data, rsa_public_key, RSA_PKCS1_PADDING);

	if (result == -1) {
		return MC_ERR_DECRYPT; // ���� ���� ����
	}

	*plain_len = result;

	return MC_ERR_OK; // ���� ���� ����
}

mc_err PublicKey_Load_RSA1024(int key_idx, int* loaded_key)
{
	// key_idx�� ��ȿ���� Ȯ��
	if (key_idx < 0 || key_idx > 0x20 || key_store[key_idx] == NULL) {
		return MC_ERR_KEY_LOAD;
	}

	// RSA ����ü���� e, n ���� (���� Ű ��Ҹ� ���)
	const BIGNUM* rsa_e = NULL;
	const BIGNUM* rsa_n = NULL;
	RSA_get0_key(key_store[key_idx], &rsa_n, &rsa_e, NULL);

	if (rsa_e == NULL || rsa_n == NULL) {
		return MC_ERR_KEY_LOAD;
	}

	// BIGNUM�� int �迭�� ��ȯ�Ͽ� ������ �� �ִ� �ִ� ũ�� ���
	int max_size = BN_num_bytes(rsa_n) + BN_num_bytes(rsa_e);

	// loaded_key �迭�� ũ�Ⱑ ������� Ȯ���ϰ� ������ ��� ���� ��ȯ
	if (max_size > sizeof(loaded_key)) {
		return MC_ERR_KEY_LOAD;
	}

	// BIGNUM�� int �迭�� ��ȯ�Ͽ� ����
	BN_bn2bin(rsa_n, (unsigned char*)loaded_key);
	BN_bn2bin(rsa_e, (unsigned char*)(loaded_key + BN_num_bytes(rsa_n)));

	return MC_ERR_OK;
}