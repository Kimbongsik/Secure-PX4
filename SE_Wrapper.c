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
	//C_APDU[APDU_CLA] = 0x80;            // CLA - Class
	//C_APDU[APDU_INS] = 0x88;            // INS - Instruction: Generate RSA Key Pair
	//C_APDU[APDU_P1] = 0x06;            // P1 - Parameter 1
	//C_APDU[APDU_P2] = (BYTE)key_num;    // P2 - Parameter 2
	//C_APDU[APDU_LC] = 0x00;             // Lc - no data for CRT key or 1 byte for non-CRT
	////C_APDU[APDU_DATA] = 0x01;           // Data absent - CRT, data present - non-CRT

	//if (iso7816.TransmitAPDU(C_APDU, 5, NULL, NULL) && SW1SW2 == 0x9000) return TRUE;
	//return FALSE;
}

mc_err Sign_RSA1024(int key_num, BYTE* plain_data, int plain_len, BYTE* sign_data, int* sign_len) {

	//C_APDU[APDU_CLA] = 0x80; // Command
	//C_APDU[APDU_INS] = 0x8B; // Instruction code (RSA_SIGN)
	//C_APDU[APDU_P1] = 0x00;
	//C_APDU[APDU_P2] = (BYTE)key_num;
	//C_APDU[APDU_LC] = (plain_len >= 256) ? 0xFF : (BYTE)plain_len;

	//memcpy(C_APDU + APDU_DATA, plain_data, plain_len);

	//if (iso7816.TransmitAPDU(C_APDU, plain_len + 5, enc_data, enc_len) && SW1SW2 == 0x9000) return TRUE;

	//return FALSE;
}

mc_err Verify_RSA1024(int key_num, BYTE* sign_data, int sign_len, BYTE* plain_data, int* plain_len) {

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

mc_err PublicKey_Load_RSA1024(int key_idx, int* loaded_key)
{
	//TODO
}