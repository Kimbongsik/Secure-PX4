#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//#include "ISO7816.h"
//#include "Script_bin.h"

#include "SE_Wrapper.h"


/*
//ISOISO7816-3

BYTE C_APDU[MAX_C_APDU_SIZE]; // Array reserved for Command APDU
BYTE R_APDU[MAX_C_APDU_SIZE]; // Array reserved for response APDU

*/


int Run() {
	
	Generate_AES128Key(0x20);
}

/*=================================================
 int Generate_AES128Key
 : SE ���� AES128 Key ���� �� NVM �� ����
 : key_num = Key Reference (Maximum: 0x20)
=================================================*/
int Generate_AES128Key(int key_num) {

	/*C_APDU[APDU_CLA] = 0x80;
	C_APDU[APDU_INS] = 0x84;
	C_APDU[APDU_P1] = 0x09;
	C_APDU[APDU_P2] = (BYTE)key_num;
	C_APDU[APDU_LC] = 0x00;

	if (iso7816.TransmitAPDU(C_APDU, 5, NULL, NULL) && SW1SW2 == 0x9000) return TRUE;
	return FALSE;*/
}

/*=================================================
 int Encrypt_AES128
 : SE �� ����� AES128 Key�� plain_data ��ȣȭ
 : key_num = Key Reference (Maximum: 0x20)
 : enc_data : SE���� ��ȣȭ�� ������ ���� ����
=================================================*/
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

/*=================================================
 int Decrypt_AES128
 : SE �� ����� AES128 Key�� enc_data ��ȣȭ
 : key_num = Key Reference (Maximum: 0x20)
 : plain_data : SE���� ��ȣȭ�� ������ ���� ����
=================================================*/
int Decrypt_AES128(int key_num, BYTE* enc_data, int enc_len, BYTE* plain_data, int* plain_len) {
	/*C_APDU[APDU_CLA] = 0x80;
	C_APDU[APDU_INS] = 0x82;
	C_APDU[APDU_P1] = 0x00;
	C_APDU[APDU_P2] = (BYTE)key_num;
	C_APDU[APDU_LC] = (BYTE)enc_len;

	memcpy(C_APDU + APDU_DATA, enc_data, enc_len);

	if (iso7816.TransmitAPDU(C_APDU, enc_len + 5, plain_data, plain_len) && SW1SW2 == 0x9000) return TRUE;
	return FALSE;*/
}

/*=================================================
int Sign_RSA1024
: SE ���� RSA1024 public_key�� plain_data ��ȣȭ
: key_num = Key Reference (Maximum: 0x20)
: ��ȣȭ�� �����ʹ� enc_data�� ����
=================================================*/
int Sign_RSA1024(int key_num, BYTE* plain_data, int plain_len, BYTE* enc_data, int* enc_len) {

	//C_APDU[APDU_CLA] = 0x80; // Command
	//C_APDU[APDU_INS] = 0x8B; // Instruction code (RSA_SIGN)
	//C_APDU[APDU_P1] = 0x00;
	//C_APDU[APDU_P2] = (BYTE)key_num;
	//C_APDU[APDU_LC] = (plain_len >= 256) ? 0xFF : (BYTE)plain_len;

	//memcpy(C_APDU + APDU_DATA, plain_data, plain_len);

	//if (iso7816.TransmitAPDU(C_APDU, plain_len + 5, enc_data, enc_len) && SW1SW2 == 0x9000) return TRUE;

	//return FALSE;
}

/*=================================================
int Verify_RSA1024
: SE ���� RSA1024 public_key�� plain_data ��ȣȭ
: key_num = Key Reference (Maximum: 0x20)
: ��ȣȭ�� �����ʹ� enc_data�� ����
=================================================*/
int Verify_RSA1024(int key_num, BYTE* plain_data, int plain_len, BYTE* enc_data, int* enc_len) {

	//C_APDU[APDU_CLA] = 0x90;
	//C_APDU[APDU_INS] = 0x8C;
	//C_APDU[APDU_P1] = 0x00;
	//C_APDU[APDU_P2] = (BYTE)key_num;
	//C_APDU[APDU_LC] = 64;

	//memcpy(C_APDU + APDU_DATA, enc_data, 64);

	//if (iso7816.TransmitAPDU(C_APDU, 64 + 5, NULL, NULL) && SW1SW2 == 0x9000) {}
	//else return FALSE;

	//BYTE buffer[64];
	//for (int i = 0; i < 64; i++) buffer[i] = enc_data[i + 64];

	//memcpy(C_APDU + APDU_DATA, buffer, 64);

	//if (iso7816.TransmitAPDU(C_APDU, 64 + 5, plain_data, plain_len) && SW1SW2 == 0x9000) return TRUE;
	//else return FALSE;
}

// Public Key Load
int PublicKey_Load_RSA1024(int key_idx)
{
	//TODO
}