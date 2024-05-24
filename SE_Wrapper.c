#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "SE_Wrapper.h"

RSA* key_store[0x21]; // 최대 0x20 (32개) 키 저장

mc_err Generate_AES128Key(BYTE* key, BYTE* iv, int key_size, int iv_size) {
	//Generate AES key
	if(RAND_bytes(key, key_size) != 1)
		return MC_ERR_KEY_GEN;

	//Generate AES iv
	if(RAND_bytes(iv, iv_size) != 1)
		return MC_ERR_KEY_GEN;

	return MC_ERR_OK;
}

mc_err Encrypt_AES128(BYTE* key, BYTE* plain_data, int plain_len, BYTE* enc_data, BYTE* iv) {
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	int len, enc_len;

	if(!ctx)
		return MC_ERR_ENCRYPT;
	
	//Initialise AES encryption(AES-CTR).
	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv))
		return MC_ERR_ENCRYPT;

	//Encrypt data and update
	if(1 != EVP_EncryptUpdate(ctx, enc_data, &len, plain_data, plain_len))
		return MC_ERR_ENCRYPT;
	enc_len = len;

	//Finalize encryption
	if(1 != EVP_EncryptFinal_ex(ctx, enc_data + len, &len))
		return MC_ERR_ENCRYPT;
	enc_len += len;
	memcpy(plain_data, enc_data, enc_len);

	EVP_CIPHER_CTX_free(ctx);
	return MC_ERR_OK;
}

mc_err Decrypt_AES128(BYTE* key, BYTE* enc_data, int enc_len, BYTE* plain_data, BYTE* iv) {
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	int len, plain_len;

	if(!ctx)
		return MC_ERR_DECRYPT;

	//Initialise AES decryption(AES-CTR).
	if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv))
		return MC_ERR_DECRYPT;

	//Decrypt data and update
	if (1 != EVP_DecryptUpdate(ctx, plain_data, &len, enc_data, enc_len))
		return MC_ERR_DECRYPT;
	plain_len = len;

	//Finalize encryption
	if (1 != EVP_DecryptFinal_ex(ctx, plain_data + len, &len))
		return MC_ERR_DECRYPT;
	plain_len += len;
	memcpy(enc_data, plain_data, plain_len);

	EVP_CIPHER_CTX_free(ctx);
	return MC_ERR_OK;
}

mc_err Generate_RSA1024Key(int key_num) {
	// key_num이 유효한지 확인
	if (key_num < 0 || key_num > 0x20) {
		return MC_ERR_KEY_GEN;
	}

	// RSA 키를 저장할 구조체 생성
	RSA* rsa = RSA_new();
	if (rsa == NULL) {
		return MC_ERR_KEY_GEN;
	}

	// 공개 지수 설정 (일반적으로 65537 사용)
	BIGNUM* e_value = BN_new();
	if (e_value == NULL) {
		RSA_free(rsa);
		return MC_ERR_KEY_GEN;
	}
	BN_set_word(e_value, RSA_F4);

	// RSA 키 생성
	int ret = RSA_generate_key_ex(rsa, 1024, e_value, NULL);

	// BIGNUM 구조체 해제
	BN_free(e_value);

	if (ret != 1) {
		RSA_free(rsa);
		return MC_ERR_KEY_GEN;
	}

	// 생성된 키를 key_store에 저장
	key_store[key_num] = rsa;

	return MC_ERR_OK;
}

mc_err Sign_RSA1024(int key_num, BYTE* plain_data, int plain_len, BYTE* sign_data, int* sign_len) {
	// key_num이 유효한지 확인
	if (key_num < 0 || key_num > 0x20 || key_store[key_num] == NULL) {
		return MC_ERR_KEY_LOAD;
	}

	// RSA 개인 키 추출
	RSA* rsa_private_key = key_store[key_num];

	// 서명할 데이터 준비
	unsigned char* digest = (unsigned char*)malloc(RSA_size(rsa_private_key));
	if (digest == NULL) {
		return MC_ERR_ENCRYPT;
	}

	// 해시 계산 (SHA-256 사용)
	unsigned int digest_len;
	EVP_MD_CTX* ctx = EVP_MD_CTX_new();
	if (ctx == NULL) {
		free(digest);
		return MC_ERR_ENCRYPT;
	}
	EVP_DigestInit_ex(ctx, EVP_sha256(), NULL); // SHA-256 사용
	EVP_DigestUpdate(ctx, plain_data, plain_len);
	EVP_DigestFinal_ex(ctx, digest, &digest_len);
	EVP_MD_CTX_free(ctx);

	// RSA 서명
	int result = RSA_private_encrypt(digest_len, digest, sign_data, rsa_private_key, RSA_PKCS1_PADDING);
	free(digest);

	if (result == -1) {
		return MC_ERR_ENCRYPT;
	}

	*sign_len = result;

	return MC_ERR_OK;
}

mc_err Verify_RSA1024(int key_num, BYTE* sign_data, int sign_len, BYTE* plain_data, int* plain_len) {
	// key_num이 유효한지 확인
	if (key_num < 0 || key_num > 0x20 || key_store[key_num] == NULL) {
		return MC_ERR_KEY_LOAD;
	}

	// RSA 공개 키 추출
	RSA* rsa_public_key = key_store[key_num];

	// 서명 검증
	int result = RSA_public_decrypt(sign_len, sign_data, plain_data, rsa_public_key, RSA_PKCS1_PADDING);

	if (result == -1) {
		return MC_ERR_DECRYPT; // 서명 검증 실패
	}

	*plain_len = result;

	return MC_ERR_OK; // 서명 검증 성공
}

mc_err PublicKey_Load_RSA1024(int key_idx, int* loaded_key)
{
	// key_idx가 유효한지 확인
	if (key_idx < 0 || key_idx > 0x20 || key_store[key_idx] == NULL) {
		return MC_ERR_KEY_LOAD;
	}

	// RSA 구조체에서 e, n 추출 (공개 키 요소만 사용)
	const BIGNUM* rsa_e = NULL;
	const BIGNUM* rsa_n = NULL;
	RSA_get0_key(key_store[key_idx], &rsa_n, &rsa_e, NULL);

	if (rsa_e == NULL || rsa_n == NULL) {
		return MC_ERR_KEY_LOAD;
	}

	// BIGNUM을 int 배열로 변환하여 저장할 수 있는 최대 크기 계산
	int max_size = BN_num_bytes(rsa_n) + BN_num_bytes(rsa_e);

	// loaded_key 배열의 크기가 충분한지 확인하고 부족할 경우 오류 반환
	if (max_size > sizeof(loaded_key)) {
		return MC_ERR_KEY_LOAD;
	}

	// BIGNUM을 int 배열로 변환하여 저장
	BN_bn2bin(rsa_n, (unsigned char*)loaded_key);
	BN_bn2bin(rsa_e, (unsigned char*)(loaded_key + BN_num_bytes(rsa_n)));

	return MC_ERR_OK;
}
